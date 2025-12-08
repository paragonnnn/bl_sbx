import platform
import sys
import traceback
import subprocess
import atexit
import concurrent
import os
import posixpath
import queue
import socket
import sqlite3
import shutil
import time
import threading
import functools
import plistlib
from pathlib import Path
from threading import Timer
from http.server import HTTPServer, SimpleHTTPRequestHandler

import asyncio
import click
import requests
from packaging.version import parse as parse_version
from pymobiledevice3.cli.cli_common import Command
from pymobiledevice3.exceptions import NoDeviceConnectedError, PyMobileDevice3Exception, DeviceNotFoundError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.diagnostics import DiagnosticsService
from pymobiledevice3.services.installation_proxy import InstallationProxyService
from pymobiledevice3.services.afc import AfcService
from pymobiledevice3.services.os_trace import OsTraceService
from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from pymobiledevice3.tunneld.api import async_get_tunneld_devices
from pymobiledevice3.services.os_trace import OsTraceService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl


def get_lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()

def start_http_server():
    handler = functools.partial(SimpleHTTPRequestHandler)
    httpd = HTTPServer(("0.0.0.0", 0), handler)
    info_queue.put((get_lan_ip(), httpd.server_port))
    httpd.serve_forever()

def find_card_paths_via_syslog(service_provider):
    """
    Monitor syslog to find Wallet card paths when user adds a card
    Returns dict with pkpass path and all file paths found
    """
    click.secho(f"\n{'='*70}", fg="cyan")
    click.secho("=== STEP 1: DISCOVERING WALLET CARD PATHS ===", fg="cyan")
    click.secho(f"{'='*70}", fg="cyan")
    click.secho("\nPlease add your card to Apple Wallet now.", fg="yellow")
    click.secho("Monitoring system logs...", fg="yellow")
    
    found_files = {}  # Dictionary: pkpass_name -> set of files
    found_paths = set()
    pkpass_name = None
    start_time = time.time()
    first_detection_time = None
    max_timeout = 70
    wait_after_detection = 25
    
    try:
        for syslog_entry in OsTraceService(lockdown=service_provider).syslog():
            message = syslog_entry.message
            
            # Look for paths in /var/mobile/Library/Passes/Cards/
            if '/var/mobile/Library/Passes/Cards/' in message:
                parts = message.split('/var/mobile/Library/Passes/Cards/')
                
                for i in range(1, len(parts)):
                    path_segment = parts[i].split()[0]
                    path_segment = path_segment.rstrip('.,;:)"\'')
                    
                    if '.pkpass' in path_segment:
                        path_parts = path_segment.split('/')
                        if len(path_parts) >= 1:
                            current_pkpass = path_parts[0]
                            
                            if current_pkpass.endswith('.pkpass'):
                                full_path = f"/var/mobile/Library/Passes/Cards/{path_segment}"
                                
                                if full_path not in found_paths:
                                    found_paths.add(full_path)
                                    
                                    if current_pkpass not in found_files:
                                        found_files[current_pkpass] = set()
                                        pkpass_name = current_pkpass
                                        # Mark first detection time
                                        if first_detection_time is None:
                                            first_detection_time = time.time()
                                            click.secho(f"\n✓ Card detected! Waiting {wait_after_detection} seconds...", fg="green")
                                    
                                    if len(path_parts) >= 2:
                                        filename = '/'.join(path_parts[1:])
                                        found_files[current_pkpass].add(filename)
                                        click.secho(f"📄 {current_pkpass}/{filename}", fg="bright_black")
            
            # Check if we should stop monitoring
            if first_detection_time and (time.time() - first_detection_time >= wait_after_detection):
                click.secho(f"\n✓ Card discovery complete!", fg="green")
                break
            
            # Overall timeout
            if time.time() - start_time > max_timeout:
                click.secho("\nTimeout reached.", fg="yellow")
                break
        
        if found_files and pkpass_name:
            click.secho(f"\n{'='*70}", fg="green")
            click.secho(f"✓ Found card: {pkpass_name}", fg="green")
            click.secho(f"{'='*70}\n", fg="green")
            
            return {
                'pkpass_name': pkpass_name,
                'pkpass_path': f"/var/mobile/Library/Passes/Cards/{pkpass_name}",
                'cache_path': f"/var/mobile/Library/Passes/Cards/{pkpass_name.replace('.pkpass', '.cache')}",
                'files': found_files[pkpass_name]
            }
        else:
            click.secho("\n✗ No card detected. Please try again.", fg="red")
            return None
            
    except Exception as e:
        click.secho(f"Error during syslog monitoring: {e}", fg="red")
        return None

def replace_card_image(service_provider, dvt, card_info, image_path, uuid, ip, port):
    """
    Replace the card background image
    """
    click.secho(f"\n{'='*70}", fg="cyan")
    click.secho("=== STEP 2: REPLACING CARD BACKGROUND IMAGE ===", fg="cyan")
    click.secho(f"{'='*70}\n", fg="cyan")
    
    afc = AfcService(lockdown=service_provider)
    pc = ProcessControl(dvt)
    
    target_path = f"{card_info['pkpass_path']}/cardBackgroundCombined@2x.png"
    
    # Copy image to root directory for HTTP server access
    temp_image_name = "cardBackgroundCombined@2x.png"
    shutil.copyfile(image_path, temp_image_name)
    click.secho(f"Prepared image for upload: {temp_image_name}", fg="green")
    
    # Modify BLDatabaseManager.sqlite
    with sqlite3.connect("BLDatabaseManager.sqlite") as bldb_conn:
        bldb_cursor = bldb_conn.cursor()
        bldb_cursor.execute("""
        UPDATE ZBLDOWNLOADINFO
        SET ZASSETPATH = ?, ZPLISTPATH = ?, ZDOWNLOADID = ?
        """, (target_path, target_path, target_path))
        
        file_url = f"http://{ip}:{port}/{temp_image_name}"
        bldb_cursor.execute("""
        UPDATE ZBLDOWNLOADINFO
        SET ZURL = ?
        """, (file_url,))
        bldb_conn.commit()
    
    # Modify downloads.28.sqlitedb
    shutil.copyfile("downloads.28.sqlitedb", "tmp.downloads.28.sqlitedb")
    conn = sqlite3.connect("tmp.downloads.28.sqlitedb")
    cursor = conn.cursor()
    bldb_local_prefix = f"/private/var/containers/Shared/SystemGroup/{uuid}/Documents/BLDatabaseManager/BLDatabaseManager.sqlite"
    cursor.execute(f"""
    UPDATE asset
    SET local_path = CASE
        WHEN local_path LIKE '%/BLDatabaseManager.sqlite'
            THEN '{bldb_local_prefix}'
        WHEN local_path LIKE '%/BLDatabaseManager.sqlite-shm'
            THEN '{bldb_local_prefix}-shm'
        WHEN local_path LIKE '%/BLDatabaseManager.sqlite-wal'
            THEN '{bldb_local_prefix}-wal'
    END
    WHERE local_path LIKE '/private/var/containers/Shared/SystemGroup/%/Documents/BLDatabaseManager/BLDatabaseManager.sqlite%'
    """)
    bldb_server_prefix = f"http://{ip}:{port}/BLDatabaseManager.sqlite"
    cursor.execute(f"""
    UPDATE asset
    SET url = CASE
        WHEN url LIKE '%/BLDatabaseManager.sqlite'
            THEN '{bldb_server_prefix}'
        WHEN url LIKE '%/BLDatabaseManager.sqlite-shm'
            THEN '{bldb_server_prefix}-shm'
        WHEN url LIKE '%/BLDatabaseManager.sqlite-wal'
            THEN '{bldb_server_prefix}-wal'
    END
    WHERE url LIKE '%/BLDatabaseManager.sqlite%'
    """)
    conn.commit()

    # Kill processes
    procs = OsTraceService(lockdown=service_provider).get_pid_list().get("Payload")
    pid_bookassetd = next((pid for pid, p in procs.items() if p['ProcessName'] == 'bookassetd'), None)
    pid_books = next((pid for pid, p in procs.items() if p['ProcessName'] == 'Books'), None)
    if pid_bookassetd:
        click.secho(f"Stopping bookassetd...", fg="yellow")
        pc.signal(pid_bookassetd, 19)
    if pid_books:
        click.secho(f"Killing Books...", fg="yellow")
        pc.kill(pid_books)
    
    # Upload image
    click.secho(f"Uploading {temp_image_name}...", fg="yellow")
    afc.push(temp_image_name, temp_image_name)

    # Upload downloads database
    click.secho("Uploading downloads database...", fg="yellow")
    afc.push("tmp.downloads.28.sqlitedb", "Downloads/downloads.28.sqlitedb")
    afc.push("tmp.downloads.28.sqlitedb-shm", "Downloads/downloads.28.sqlitedb-shm")
    afc.push("tmp.downloads.28.sqlitedb-wal", "Downloads/downloads.28.sqlitedb-wal")
    
    # Kill itunesstored
    procs = OsTraceService(lockdown=service_provider).get_pid_list().get("Payload")
    pid_itunesstored = next((pid for pid, p in procs.items() if p['ProcessName'] == 'itunesstored'), None)
    if pid_itunesstored:
        click.secho(f"Triggering download...", fg="yellow")
        pc.kill(pid_itunesstored)
    
    # Wait for download
    click.secho("Waiting for download to complete...", fg="yellow")
    download_start_time = time.time()
    download_timeout = 20  # 10 seconds after HTTP requests appear
    http_request_detected = False
    
    for syslog_entry in OsTraceService(lockdown=service_provider).syslog():
        if "Install complete for download: 6936249076851270150" in syslog_entry.message:
            break
        # Check if we've waited 10 seconds after HTTP requests would typically appear
        if time.time() - download_start_time > download_timeout:
            break
    
    # Kill processes again
    procs = OsTraceService(lockdown=service_provider).get_pid_list().get("Payload")
    pid_bookassetd = next((pid for pid, p in procs.items() if p['ProcessName'] == 'bookassetd'), None)
    pid_books = next((pid for pid, p in procs.items() if p['ProcessName'] == 'Books'), None)
    if pid_bookassetd:
        pc.kill(pid_bookassetd)
    if pid_books:
        pc.kill(pid_books)
    
    # Relaunch Books
    try:
        pc.launch("com.apple.iBooks")
    except Exception as e:
        click.secho(f"Error launching Books app: {e}", fg="red")
        conn.close()
        return False
    
    click.secho("Waiting for file overwrite...", fg="yellow")
    success_message = f"{target_path}) [Install-Mgr]: Marking download as [finished]"
    timeout = time.time() + 15  # Increased from 30 to 40
    success_detected = False
    
    for syslog_entry in OsTraceService(lockdown=service_provider).syslog():
        if time.time() > timeout:
            break
        if (posixpath.basename(syslog_entry.filename) == 'bookassetd') and \
                success_message in syslog_entry.message:
            click.secho("✓ Image replacement confirmed!", fg="green")
            success_detected = True
            break
    
    procs = OsTraceService(lockdown=service_provider).get_pid_list().get("Payload")
    pid_bookassetd = next((pid for pid, p in procs.items() if p['ProcessName'] == 'bookassetd'), None)
    if pid_bookassetd:
        pc.kill(pid_bookassetd)
    
    conn.close()
    if success_detected:
        click.secho("✓ Image replacement complete!\n", fg="green")
    else:
        click.secho("✓ Image replacement complete!\n", fg="green")
    return True

def clear_cache_file(service_provider, dvt, cache_path, cache_filename, ip, port, uuid):
    """Clear a single cache file"""
    afc = AfcService(lockdown=service_provider)
    pc = ProcessControl(dvt)
    
    full_path = f"{cache_path}/{cache_filename}"
    
    # Modify BLDatabaseManager.sqlite
    with sqlite3.connect("BLDatabaseManager.sqlite") as bldb_conn:
        bldb_cursor = bldb_conn.cursor()
        bldb_cursor.execute("""
        UPDATE ZBLDOWNLOADINFO
        SET ZASSETPATH = ?, ZPLISTPATH = ?, ZDOWNLOADID = ?
        """, (full_path, full_path, full_path))
        
        file_url = f"http://{ip}:{port}/{cache_filename}"
        bldb_cursor.execute("""
        UPDATE ZBLDOWNLOADINFO
        SET ZURL = ?
        """, (file_url,))
        bldb_conn.commit()
    
    # Modify downloads.28.sqlitedb
    shutil.copyfile("downloads.28.sqlitedb", "tmp.downloads.28.sqlitedb")
    conn = sqlite3.connect("tmp.downloads.28.sqlitedb")
    cursor = conn.cursor()
    bldb_local_prefix = f"/private/var/containers/Shared/SystemGroup/{uuid}/Documents/BLDatabaseManager/BLDatabaseManager.sqlite"
    cursor.execute(f"""
    UPDATE asset
    SET local_path = CASE
        WHEN local_path LIKE '%/BLDatabaseManager.sqlite'
            THEN '{bldb_local_prefix}'
        WHEN local_path LIKE '%/BLDatabaseManager.sqlite-shm'
            THEN '{bldb_local_prefix}-shm'
        WHEN local_path LIKE '%/BLDatabaseManager.sqlite-wal'
            THEN '{bldb_local_prefix}-wal'
    END
    WHERE local_path LIKE '/private/var/containers/Shared/SystemGroup/%/Documents/BLDatabaseManager/BLDatabaseManager.sqlite%'
    """)
    bldb_server_prefix = f"http://{ip}:{port}/BLDatabaseManager.sqlite"
    cursor.execute(f"""
    UPDATE asset
    SET url = CASE
        WHEN url LIKE '%/BLDatabaseManager.sqlite'
            THEN '{bldb_server_prefix}'
        WHEN url LIKE '%/BLDatabaseManager.sqlite-shm'
            THEN '{bldb_server_prefix}-shm'
        WHEN url LIKE '%/BLDatabaseManager.sqlite-wal'
            THEN '{bldb_server_prefix}-wal'
    END
    WHERE url LIKE '%/BLDatabaseManager.sqlite%'
    """)
    conn.commit()

    # Kill processes
    procs = OsTraceService(lockdown=service_provider).get_pid_list().get("Payload")
    pid_bookassetd = next((pid for pid, p in procs.items() if p['ProcessName'] == 'bookassetd'), None)
    pid_books = next((pid for pid, p in procs.items() if p['ProcessName'] == 'Books'), None)
    if pid_bookassetd:
        pc.signal(pid_bookassetd, 19)
    if pid_books:
        pc.kill(pid_books)
    
    # Upload empty cache file
    click.secho(f"  Uploading empty {cache_filename}...", fg="yellow")
    afc.push(cache_filename, cache_filename)

    # Upload downloads database
    afc.push("tmp.downloads.28.sqlitedb", "Downloads/downloads.28.sqlitedb")
    afc.push("tmp.downloads.28.sqlitedb-shm", "Downloads/downloads.28.sqlitedb-shm")
    afc.push("tmp.downloads.28.sqlitedb-wal", "Downloads/downloads.28.sqlitedb-wal")
    
    # Kill itunesstored
    procs = OsTraceService(lockdown=service_provider).get_pid_list().get("Payload")
    pid_itunesstored = next((pid for pid, p in procs.items() if p['ProcessName'] == 'itunesstored'), None)
    if pid_itunesstored:
        pc.kill(pid_itunesstored)
    
    # Wait for download
    download_start_time = time.time()
    download_timeout = 10  # 10 seconds after HTTP requests
    
    for syslog_entry in OsTraceService(lockdown=service_provider).syslog():
        if "Install complete for download: 6936249076851270150" in syslog_entry.message:
            break
        if time.time() - download_start_time > download_timeout:
            break
    
    # Kill processes again
    procs = OsTraceService(lockdown=service_provider).get_pid_list().get("Payload")
    pid_bookassetd = next((pid for pid, p in procs.items() if p['ProcessName'] == 'bookassetd'), None)
    pid_books = next((pid for pid, p in procs.items() if p['ProcessName'] == 'Books'), None)
    if pid_bookassetd:
        pc.kill(pid_bookassetd)
    if pid_books:
        pc.kill(pid_books)
    
    # Relaunch Books
    try:
        pc.launch("com.apple.iBooks")
    except Exception as e:
        click.secho(f"  Error launching Books app: {e}", fg="red")
        return False
    
    success_message = f"{full_path}) [Install-Mgr]: Marking download as [finished]"
    timeout = time.time() + 20
    
    for syslog_entry in OsTraceService(lockdown=service_provider).syslog():
        if time.time() > timeout:
            break
        if (posixpath.basename(syslog_entry.filename) == 'bookassetd') and \
                success_message in syslog_entry.message:
            break
    
    procs = OsTraceService(lockdown=service_provider).get_pid_list().get("Payload")
    pid_bookassetd = next((pid for pid, p in procs.items() if p['ProcessName'] == 'bookassetd'), None)
    if pid_bookassetd:
        pc.kill(pid_bookassetd)
    
    conn.close()
    return True

def clear_wallet_cache(service_provider, dvt, card_info, ip, port, uuid):
    """Clear all cache files"""
    click.secho(f"\n{'='*70}", fg="cyan")
    click.secho("=== STEP 3: CLEARING WALLET CACHE ===", fg="cyan")
    click.secho(f"{'='*70}\n", fg="cyan")
    
    # Create empty files
    cache_files = ["FrontFace", "PlaceHolder", "Preview"]
    for filename in cache_files:
        with open(filename, "wb") as f:
            pass
    click.secho("Created empty cache files", fg="green")
    
    for idx, cache_file in enumerate(cache_files, 1):
        click.secho(f"\n[{idx}/{len(cache_files)}] Clearing {cache_file}...", fg="cyan")
        success = clear_cache_file(service_provider, dvt, card_info['cache_path'], 
                                   cache_file, ip, port, uuid)
        if not success:
            click.secho(f"  ✗ Failed to clear {cache_file}", fg="red")
            return False
        click.secho(f"  ✓ {cache_file} cleared!", fg="green")
        
        if idx < len(cache_files):
            time.sleep(2)
    
    click.secho("\n✓ All cache files cleared!\n", fg="green")
    return True

def main_callback(service_provider: LockdownClient, dvt: DvtSecureSocketProxyService):
    # Start HTTP server
    http_thread = threading.Thread(target=start_http_server, daemon=True)
    http_thread.start()
    ip, port = info_queue.get()
    click.secho(f"HTTP server: http://{ip}:{port}/", fg="bright_black")

    afc = AfcService(lockdown=service_provider)
    pc = ProcessControl(dvt)
    
    # Get UUID
    uuid = open("uuid.txt", "r").read().strip() if Path("uuid.txt").exists() else ""
    if len(uuid) < 10:
        try:
            pc.launch("com.apple.iBooks")
        except Exception as e:
            click.secho(f"Error launching Books app: {e}", fg="red")
            return
        click.secho("Finding bookassetd container UUID...", fg="yellow")
        click.secho("Please open Books app and download a book to continue.", fg="yellow")
        for syslog_entry in OsTraceService(lockdown=service_provider).syslog():
            if (posixpath.basename(syslog_entry.filename) != 'bookassetd') or \
                    not "/Documents/BLDownloads/" in syslog_entry.message:
                continue
            uuid = syslog_entry.message.split("/var/containers/Shared/SystemGroup/")[1] \
                    .split("/Documents/BLDownloads")[0]
            click.secho(f"Found UUID: {uuid}", fg="green")
            with open("uuid.txt", "w") as f:
                f.write(uuid)
            break
    else:
        click.secho(f"Using saved UUID: {uuid}", fg="green")
    
    # STEP 1: Find card paths
    card_info = find_card_paths_via_syslog(service_provider)
    if not card_info:
        click.secho("Failed to find card. Exiting.", fg="red")
        sys.exit(1)
    
    # Check if image exists
    image_path = "images/cardBackgroundCombined@2x.png"
    if not os.path.exists(image_path):
        click.secho(f"\n✗ Error: Image not found at {image_path}", fg="red")
        click.secho("Please place your 1536x969px image in the /images folder", fg="red")
        sys.exit(1)
    
    # STEP 2: Replace card image
    success = replace_card_image(service_provider, dvt, card_info, image_path, uuid, ip, port)
    if not success:
        click.secho("Failed to replace image. Exiting.", fg="red")
        sys.exit(1)
    
    time.sleep(3)
    
    # STEP 3: Clear cache
    success = clear_wallet_cache(service_provider, dvt, card_info, ip, port, uuid)
    if not success:
        click.secho("Failed to clear cache. Exiting.", fg="red")
        sys.exit(1)
    
    # Final respring
    click.secho(f"\n{'='*70}", fg="green")
    click.secho("=== ALL STEPS COMPLETED ===", fg="green")
    click.secho(f"{'='*70}\n", fg="green")
    click.secho("Respringing device...", fg="yellow")
    procs = OsTraceService(lockdown=service_provider).get_pid_list().get("Payload")
    pid = next((pid for pid, p in procs.items() if p['ProcessName'] == 'backboardd'), None)
    if pid:
        pc.kill(pid)
    
    click.secho("\n✓ Done!", fg="green")
    click.secho(f"\n{'='*70}", fg="yellow")
    click.secho("⚠️  ATTENTION ⚠️", fg="red", bold=True)
    click.secho(f"{'='*70}", fg="yellow")
    click.secho("\nPlease REBOOT your device now (hold power + volume button).", fg="yellow")
    click.secho("\nIf the device boots to the setup screen:", fg="yellow")
    click.secho("1. Go through the setup screens normally", fg="cyan")
    click.secho("2. At 'iPhone Partially Set Up' screen, tap 'Continue with Partial Setup'", fg="cyan")
    click.secho("3. Enter your iCloud password if asked", fg="cyan")
    click.secho("4. YOU WILL NOT LOSE ANY DATA", fg="cyan")
    click.secho(f"\n{'='*70}\n", fg="yellow")
    
    sys.exit(0)

async def _run_async_rsd_connection(address, port):
    try:
        async def async_connection():
            async with RemoteServiceDiscoveryService((address, port)) as rsd:
                click.secho("Connected to tunnel", fg="green")
                loop = asyncio.get_running_loop()
                    
                def run_blocking_callback():
                    with DvtSecureSocketProxyService(rsd) as dvt:
                        main_callback(rsd, dvt)
                    
                await loop.run_in_executor(None, run_blocking_callback)

        await async_connection()
        return

    except (ConnectionRefusedError, OSError) as e:
        click.secho(f"Tunnel connect failed: {e}", fg="red")
        raise

def exit_func(tunnel_proc):
    tunnel_proc.terminate()

async def create_tunnel(udid):
    command = [
        sys.executable,
        "-m", "pymobiledevice3",
        "lockdown", "start-tunnel",
        "--script-mode",
        "--udid", udid
    ]
    tunnel_process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    atexit.register(exit_func, tunnel_process)
    while True:
        output = tunnel_process.stdout.readline()
        if output:
            rsd_val = output.decode().strip()
            break
        if tunnel_process.poll() is not None:
            error = tunnel_process.stderr.readlines()
            if error:
                not_connected = None
                admin_error = None
                for i in range(len(error)):
                    if (error[i].find(b'connected') > -1):
                        not_connected = True
                    if (error[i].find(b'admin') > -1):
                        admin_error = True
                if not_connected:
                    print("Device not connected.", error)
                elif admin_error:
                    print("Run as admin.", error)
                else:
                    print("Tunnel error.", error)
                sys.exit()
            break
    rsd_str = str(rsd_val)
    click.secho(f"Successfully created tunnel: {rsd_str}", fg="green")
    time.sleep(2)
    return {"address": rsd_str.split(" ")[0], "port": int(rsd_str.split(" ")[1])}

async def connection_context(service_provider):
    try:
        marketing_name = service_provider.get_value(key="MarketingName")
        device_build = service_provider.get_value(key="BuildVersion")
        device_product_type = service_provider.get_value(key="ProductType")
        device_version = parse_version(service_provider.product_version)
        click.secho(f"\nDevice: {marketing_name} (iOS {device_version}, Build {device_build})", fg="blue")
        click.secho("Keep device unlocked during the process.\n", fg="blue")
        
        if device_version >= parse_version('17.0'):
            available_address = await create_tunnel(service_provider.udid)
            if available_address:
                await _run_async_rsd_connection(available_address["address"], available_address["port"])
            else:
                raise Exception("Error getting tunnel addresses")
        else:
            with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
                main_callback(service_provider, dvt)
    except OSError:
        pass
    except DeviceNotFoundError:
        click.secho("Device not found. Make sure it's unlocked.", fg="red")
    except Exception as e:
        raise Exception(f"Connection not established: {e}")

if __name__ == "__main__":
    click.secho("\n" + "="*70, fg="cyan")
    click.secho("     WALLET CARD BACKGROUND MODIFIER", fg="cyan", bold=True)
    click.secho("="*70 + "\n", fg="cyan")
    
    click.secho("PREREQUISITES:", fg="yellow", bold=True)
    click.secho("1. Delete the card from Apple Wallet if it already exists", fg="white")
    click.secho("2. Have your card ready to add to Wallet when prompted\n", fg="white")
    
    response = input("Ready to continue? (y/n): ")
    if response.lower() != 'y':
        click.secho("Exiting.", fg="yellow")
        sys.exit(0)
    
    # Check if image exists
    if not os.path.exists("images/cardBackgroundCombined@2x.png"):
        click.secho("\n✗ Error: Image not found at images/cardBackgroundCombined@2x.png", fg="red")
        click.secho("Please place your image in the /images folder first.", fg="red")
        sys.exit(1)
    
    lockdown = create_using_usbmux()
    info_queue = queue.Queue()
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    asyncio.run(connection_context(lockdown))