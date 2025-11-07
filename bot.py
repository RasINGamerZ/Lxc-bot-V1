import os
import discord
import docker
import sqlite3
import asyncio
import random
import string
import json
import time
import paramiko
import logging
from datetime import datetime, timedelta
from discord import app_commands
from discord.ext import commands, tasks
from dotenv import load_dotenv
from typing import Optional, List
import aiosqlite
import psutil
import subprocess
import platform
import socket
import uuid
import hashlib
import io

# Load environment variables
load_dotenv()

# Bot configuration
TOKEN = os.getenv('DISCORD_TOKEN')
ADMIN_IDS = [int(id) for id in os.getenv('ADMIN_IDS', '').split(',') if id.strip()]
ADMIN_ROLE_ID = int(os.getenv('ADMIN_ROLE_ID', '0'))
DEFAULT_OS_IMAGE = os.getenv('DEFAULT_OS_IMAGE', 'ubuntu:22.04')
LXC_STORAGE_PATH = os.getenv('LXC_STORAGE_PATH', '/var/lib/lxc')
MAX_CONTAINERS = int(os.getenv('MAX_CONTAINERS', '100'))
MAX_VPS_PER_USER = int(os.getenv('MAX_VPS_PER_USER', '3'))

# Bot setup
intents = discord.Intents.default()
intents.guilds = True
intents.members = True
intents.messages = True
intents.message_content = True

bot = commands.Bot(command_prefix=['/', '-'], intents=intents, help_command=None)

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('chunkhost_lxc_bot')

# Auto responses
AUTO_RESPONSES = {
    "yoo": "Yo 😎",
    "give me vps": "Only admins can create VPS instances. Please contact an admin.",
    "who are you?": "I am MrDraynoX 😍 LXC VPS Management Bot",
    "subscribe": "Subscribe MrDraynoX 😍",
    "bye": "Bye 😢",
    "best": "I am the best LXC VPS bot ever 👑",
    "vps": "VPS management is admin-only. Use /help to see available commands.",
    "admin": "Admins can create and manage VPS instances using the deploy command.",
    "lxc": "I use LXC containers for lightweight virtualization."
}

# Initialize database
async def init_db():
    async with aiosqlite.connect('chunkhost_lxc.db') as db:
        # Users table
        await db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                discord_id INTEGER UNIQUE,
                total_invites INTEGER DEFAULT 0,
                real_invites INTEGER DEFAULT 0,
                fake_invites INTEGER DEFAULT 0,
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # VPS table
        await db.execute('''
            CREATE TABLE IF NOT EXISTS vps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                container_name TEXT,
                container_id TEXT,
                ram INTEGER,
                cpu INTEGER,
                disk INTEGER,
                ssh_port INTEGER,
                status TEXT DEFAULT 'running',
                os_type TEXT DEFAULT 'ubuntu',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                ip_address TEXT
            )
        ''')
        
        # Activity logs table
        await db.execute('''
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        await db.commit()
        logger.info("LXC Database initialized successfully")

# Helper functions
async def is_admin(ctx):
    return ctx.author.id in ADMIN_IDS or any(role.id == ADMIN_ROLE_ID for role in ctx.author.roles)

async def is_admin_interaction(interaction):
    return interaction.user.id in ADMIN_IDS or any(role.id == ADMIN_ROLE_ID for role in interaction.user.roles)

async def get_user_vps_count(user_id):
    async with aiosqlite.connect('chunkhost_lxc.db') as db:
        cursor = await db.execute('SELECT COUNT(*) FROM vps WHERE user_id = ?', (user_id,))
        result = await cursor.fetchone()
        return result[0] if result else 0

async def get_vps_info(vps_id):
    async with aiosqlite.connect('chunkhost_lxc.db') as db:
        cursor = await db.execute(
            'SELECT * FROM vps WHERE id = ?',
            (vps_id,)
        )
        return await cursor.fetchone()

async def log_activity(user_id, action, details):
    async with aiosqlite.connect('chunkhost_lxc.db') as db:
        await db.execute(
            'INSERT INTO activity_logs (user_id, action, details) VALUES (?, ?, ?)',
            (user_id, action, details)
        )
        await db.commit()

def generate_password(length=12):
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(random.choice(chars) for _ in range(length))

def generate_container_name():
    return f"lxc-vps-{uuid.uuid4().hex[:8]}"

def generate_ssh_port():
    # Generate a random port between 22000-22999
    return random.randint(22000, 22999)

async def create_lxc_container(user_id, ram, cpu, disk, os_type="ubuntu"):
    try:
        # Generate container details
        container_name = generate_container_name()
        ssh_port = generate_ssh_port()
        username = f"user{user_id}"
        password = generate_password()
        
        # Create LXC container
        container_id = f"lxc-vps-{uuid.uuid4().hex[:8]}"
        
        # LXC command to create container
        create_cmd = [
            "lxc-create",
            "-n", container_name,
            "-t", os_type,
            "--config", "user.user-data",
            "--",
            "packages", "openssh-server,curl,wget,nano,htop",
            "user.name", username,
            "user.password", password,
            "user.sudo", "ALL=(ALL) NOPASSWD:ALL"
        ]
        
        # Create container
        result = subprocess.run(create_cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            logger.error(f"Failed to create LXC container: {result.stderr}")
            return None
        
        # Start the container
        subprocess.run(["lxc-start", "-n", container_name], check=True)
        
        # Wait for container to be ready
        await asyncio.sleep(3)
        
        # Setup SSH
        ssh_setup_cmd = [
            "lxc-attach", "-n", container_name, "--",
            "bash", "-c", f"""
                systemctl enable ssh
                systemctl start ssh
                sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
                echo 'root:{password}' | chpasswd
                mkdir -p /run/sshd
                /usr/sbin/sshd
            """
        ]
        
        subprocess.run(ssh_setup_cmd, check=True)
        
        # Get container IP
        ip_result = subprocess.run(
            ["lxc-info", "-n", container_name, "-iH"],
            capture_output=True, text=True
        )
        ip_address = ip_result.stdout.strip()
        
        # Save to database
        async with aiosqlite.connect('chunkhost_lxc.db') as db:
            await db.execute(
                '''INSERT INTO vps 
                   (user_id, container_name, container_id, ram, cpu, disk, ssh_port, os_type, ip_address) 
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (user_id, container_name, container_id, ram, cpu, disk, ssh_port, os_type, ip_address)
            )
            await db.commit()
            
            # Get the VPS ID
            cursor = await db.execute('SELECT last_insert_rowid()')
            vps_id = (await cursor.fetchone())[0]
        
        # Log activity
        await log_activity(user_id, "CREATE_LXC_VPS", f"Created LXC VPS #{vps_id} with {ram}GB RAM, {cpu} CPU, {disk}GB disk")
        
        return {
            "id": vps_id,
            "container_name": container_name,
            "container_id": container_id,
            "username": username,
            "password": password,
            "ssh_port": ssh_port,
            "ip_address": ip_address,
            "ram": ram,
            "cpu": cpu,
            "disk": disk,
            "os_type": os_type
        }
    except Exception as e:
        logger.error(f"Failed to create LXC container: {e}")
        return None

async def delete_lxc_container(vps_id):
    try:
        async with aiosqlite.connect('chunkhost_lxc.db') as db:
            cursor = await db.execute('SELECT container_name FROM vps WHERE id = ?', (vps_id,))
            result = await cursor.fetchone()
        
        if result:
            container_name = result[0]
            try:
                # Stop and delete container
                subprocess.run(["lxc-stop", "-n", container_name], check=True)
                subprocess.run(["lxc-delete", "-n", container_name], check=True)
                
                await db.execute('DELETE FROM vps WHERE id = ?', (vps_id,))
                await db.commit()
                await log_activity(0, "DELETE_LXC_VPS", f"Deleted LXC VPS #{vps_id}")
                return True
            except Exception as e:
                logger.error(f"Failed to delete LXC container: {e}")
                return False
        return False
    except Exception as e:
        logger.error(f"Failed to delete LXC VPS: {e}")
        return False

# Bot events
@bot.event
async def on_ready():
    logger.info(f'Logged in as {bot.user.name}')
    await init_db()
    await bot.change_presence(
        activity=discord.Activity(
            type=discord.ActivityType.watching,
            name="LXC VPS Management | Admin Only"
        )
    )
    
    # Sync slash commands
    try:
        synced = await bot.tree.sync()
        logger.info(f"Synced {len(synced)} command(s)")
    except Exception as e:
        logger.error(f"Failed to sync commands: {e}")

@bot.event
async def on_message(message):
    # Process commands
    await bot.process_commands(message)
    
    # Auto responses
    if not message.author.bot:
        content = message.content.lower()
        for trigger, response in AUTO_RESPONSES.items():
            if trigger in content:
                await message.channel.send(response)
                break

# ==================== SLASH COMMANDS ====================

@bot.tree.command(name="help", description="Show all available commands")
async def slash_help(interaction: discord.Interaction):
    embed = discord.Embed(
        title="Chunkhost LXC VPS Management Bot",
        description="Admin-only LXC container management system",
        color=discord.Color.blue()
    )
    
    user_commands = [
        "`/help` - Show this help message",
        "`/myvps` - Show your LXC VPS instances",
        "`/status` - Show VPS resource usage",
        "`/re-ssh` - Regenerate SSH access",
        "`/info` - Show system information",
        "`/ping` - Check bot latency",
        "`/uptime` - Show system uptime",
        "`/who-made` - Bot information"
    ]
    
    admin_commands = [
        "`/deploy` - Create a new LXC VPS",
        "`/delete-vps` - Delete a VPS",
        "`/stop-vps` - Stop a VPS",
        "`/start-vps` - Start a VPS",
        "`/restart-vps` - Restart a VPS",
        "`/freeze-vps` - Freeze a VPS",
        "`/unfreeze-vps` - Unfreeze a VPS",
        "`/upgrade-vps` - Upgrade VPS resources",
        "`/list-containers` - List all LXC containers",
        "`/system-stats` - Show system statistics",
        "`/server-info` - Show server information",
        "`/network-info` - Show network information",
        "`/disk-usage` - Show disk usage",
        "`/process-list` - Show running processes",
        "`/service-status` - Show service status",
        "`/log-activity` - Show activity logs",
        "`/clear-logs` - Clear activity logs",
        "`/set-expiry` - Set VPS expiry date",
        "`/extend-vps` - Extend VPS expiry",
        "`/clone-vps` - Clone an existing VPS",
        "`/snapshot-vps` - Create VPS snapshot",
        "`/restore-snapshot` - Restore from snapshot",
        "`/exec-command` - Execute command in VPS",
        "`/install-package` - Install package on VPS",
        "`/user-management` - Manage VPS users",
        "`/firewall-rules` - Manage firewall rules",
        "`/monitor-vps` - Start VPS monitoring",
        "`/backup-vps` - Create VPS backup",
        "`/cleanup` - Cleanup unused resources"
    ]
    
    embed.add_field(name="👤 User Commands", value="\n".join(user_commands), inline=False)
    
    if interaction.user.id in ADMIN_IDS or any(role.id == ADMIN_ROLE_ID for role in interaction.user.roles):
        embed.add_field(name="👑 Admin Commands", value="\n".join(admin_commands), inline=False)
        embed.set_footer(text="Total Commands: 25+ | LXC Container Management")
    
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="who-made", description="Information about the bot creator")
async def slash_who_made(interaction: discord.Interaction):
    embed = discord.Embed(
        title="Bot Information",
        description="Made by MrDraynoX 😍",
        color=discord.Color.purple()
    )
    embed.add_field(name="Version", value="3.0 LXC Edition", inline=True)
    embed.add_field(name="Type", value="LXC VPS Management Bot", inline=True)
    embed.add_field(name="Technology", value="LXC Containers", inline=True)
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="myvps", description="Show your LXC VPS instances")
async def slash_myvps(interaction: discord.Interaction):
    user_id = interaction.user.id
    
    async with aiosqlite.connect('chunkhost_lxc.db') as db:
        cursor = await db.execute('SELECT * FROM vps WHERE user_id = ?', (user_id,))
        vps_list = await cursor.fetchall()
    
    if not vps_list:
        await interaction.response.send_message("You don't have any LXC VPS instances.")
        return
    
    embed = discord.Embed(
        title="Your LXC VPS Instances",
        description=f"You have {len(vps_list)} VPS instance(s)",
        color=discord.Color.green()
    )
    
    for vps in vps_list:
        vps_id, _, container_name, _, ram, cpu, disk, ssh_port, status, os_type, created_at, expires_at, ip_address = vps
        embed.add_field(
            name=f"VPS #{vps_id} - {status.upper()}",
            value=f"Container: {container_name}\nOS: {os_type} | RAM: {ram}GB | CPU: {cpu} | Disk: {disk}GB\n"
                   f"IP: {ip_address} | SSH: {ssh_port}\n"
                   f"Created: {created_at}\n"
                   f"Expires: {expires_at or 'Never'}",
            inline=False
        )
    
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="status", description="Show LXC VPS resource usage")
@app_commands.describe(vps_id="The ID of the VPS")
async def slash_status(interaction: discord.Interaction, vps_id: int):
    user_id = interaction.user.id
    
    # Check if VPS belongs to user or user is admin
    async with aiosqlite.connect('chunkhost_lxc.db') as db:
        cursor = await db.execute(
            'SELECT * FROM vps WHERE id = ? AND user_id = ?',
            (vps_id, user_id)
        )
        vps = await cursor.fetchone()
    
    if not vps and not (interaction.user.id in ADMIN_IDS or any(role.id == ADMIN_ROLE_ID for role in interaction.user.roles)):
        await interaction.response.send_message("You don't own this VPS or it doesn't exist.")
        return
    
    try:
        async with aiosqlite.connect('chunkhost_lxc.db') as db:
            cursor = await db.execute('SELECT * FROM vps WHERE id = ?', (vps_id,))
            vps = await cursor.fetchone()
        
        container_name = vps[2]
        
        # Get container status
        status_result = subprocess.run(
            ["lxc-info", "-n", container_name, "-s"],
            capture_output=True, text=True
        )
        
        # Get container resources
        cpu_result = subprocess.run(
            ["lxc-info", "-n", container_name, "-c"],
            capture_output=True, text=True
        )
        
        # Get memory usage
        memory_result = subprocess.run(
            ["lxc-info", "-n", container_name, "-m"],
            capture_output=True, text=True
        )
        
        embed = discord.Embed(
            title=f"LXC VPS #{vps_id} Status",
            color=discord.Color.blue()
        )
        
        embed.add_field(name="Status", value=status_result.stdout.strip(), inline=True)
        embed.add_field(name="CPU Usage", value=cpu_result.stdout.strip(), inline=True)
        embed.add_field(name="Memory Usage", value=memory_result.stdout.strip(), inline=True)
        embed.add_field(name="Container Name", value=container_name, inline=True)
        embed.add_field(name="OS Type", value=vps[8], inline=True)
        embed.add_field(name="IP Address", value=vps[11], inline=True)
        embed.add_field(name="SSH Port", value=vps[6], inline=True)
        
        await interaction.response.send_message(embed=embed)
    except Exception as e:
        logger.error(f"Failed to get VPS status: {e}")
        await interaction.response.send_message(f"Failed to get VPS status: {str(e)}")

@bot.tree.command(name="re-ssh", description="Regenerate SSH access for your VPS")
@app_commands.describe(vps_id="The ID of the VPS")
async def slash_re_ssh(interaction: discord.Interaction, vps_id: int):
    user_id = interaction.user.id
    
    # Check if VPS belongs to user or user is admin
    async with aiosqlite.connect('chunkhost_lxc.db') as db:
        cursor = await db.execute(
            'SELECT * FROM vps WHERE id = ? AND user_id = ?',
            (vps_id, user_id)
        )
        vps = await cursor.fetchone()
    
    if not vps and not (interaction.user.id in ADMIN_IDS or any(role.id == ADMIN_ROLE_ID for role in interaction.user.roles)):
        await interaction.response.send_message("You don't own this VPS or it doesn't exist.")
        return
    
    try:
        async with aiosqlite.connect('chunkhost_lxc.db') as db:
            cursor = await db.execute('SELECT * FROM vps WHERE id = ?', (vps_id,))
            vps = await cursor.fetchone()
        
        container_name = vps[2]
        new_ssh_port = generate_ssh_port()
        
        # Update SSH port in container
        subprocess.run([
            "lxc-attach", "-n", container_name, "--",
            "bash", "-c", f"""
                sed -i 's/Port 22/Port {new_ssh_port}/' /etc/ssh/sshd_config
                systemctl restart ssh
            """
        ], check=True)
        
        # Update database
        async with aiosqlite.connect('chunkhost_lxc.db') as db:
            await db.execute(
                'UPDATE vps SET ssh_port = ? WHERE id = ?',
                (new_ssh_port, vps_id)
            )
            await db.commit()
        
        ssh_link = f"ssh user{vps[1]}@{vps[11]} -p {new_ssh_port}"
        
        await interaction.response.send_message(f"SSH access for VPS #{vps_id} has been regenerated. Check your DMs.")
        await interaction.user.send(f"Your new SSH access for VPS #{vps_id}:\n\n"
                                   f"🔒 SSH: {ssh_link}")
        await log_activity(user_id, "REGEN_SSH", f"Regenerated SSH for VPS #{vps_id}")
    except Exception as e:
        logger.error(f"Failed to regenerate SSH: {e}")
        await interaction.response.send_message(f"Failed to regenerate SSH: {str(e)}")

@bot.tree.command(name="info", description="Show system information")
async def slash_info(interaction: discord.Interaction):
    try:
        # System information
        system_info = platform.uname()
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # LXC information
        lxc_version_result = subprocess.run(["lxc-version"], capture_output=True, text=True)
        lxc_version = lxc_version_result.stdout.strip()
        
        embed = discord.Embed(
            title="System Information",
            color=discord.Color.blue()
        )
        
        embed.add_field(name="System", value=system_info.system, inline=True)
        embed.add_field(name="Node", value=system_info.node, inline=True)
        embed.add_field(name="Release", value=system_info.release, inline=True)
        embed.add_field(name="Version", value=system_info.version[:50] + "...", inline=True)
        embed.add_field(name="Machine", value=system_info.machine, inline=True)
        embed.add_field(name="Processor", value=system_info.processor[:30] + "...", inline=True)
        embed.add_field(name="LXC Version", value=lxc_version, inline=True)
        embed.add_field(name="Total Memory", value=f"{memory.total / (1024**3):.2f} GB", inline=True)
        embed.add_field(name="Available Memory", value=f"{memory.available / (1024**3):.2f} GB", inline=True)
        embed.add_field(name="Disk Total", value=f"{disk.total / (1024**3):.2f} GB", inline=True)
        embed.add_field(name="Disk Used", value=f"{disk.used / (1024**3):.2f} GB", inline=True)
        embed.add_field(name="Disk Free", value=f"{disk.free / (1024**3):.2f} GB", inline=True)
        
        await interaction.response.send_message(embed=embed)
    except Exception as e:
        await interaction.response.send_message(f"Failed to get system information: {str(e)}")

@bot.tree.command(name="ping", description="Check bot latency")
async def slash_ping(interaction: discord.Interaction):
    latency = round(bot.latency * 1000)
    await interaction.response.send_message(f"🏓 Pong! Latency: {latency}ms")

@bot.tree.command(name="uptime", description="Show system uptime")
async def slash_uptime(interaction: discord.Interaction):
    try:
        uptime_seconds = time.time() - psutil.boot_time()
        days = int(uptime_seconds // 86400)
        hours = int((uptime_seconds % 86400) // 3600)
        minutes = int((uptime_seconds % 3600) // 60)
        
        embed = discord.Embed(
            title="System Uptime",
            description=f"System has been up for {days} days, {hours} hours, {minutes} minutes",
            color=discord.Color.green()
        )
        
        await interaction.response.send_message(embed=embed)
    except Exception as e:
        await interaction.response.send_message(f"Failed to get uptime: {str(e)}")

# ==================== ADMIN SLASH COMMANDS ====================

@bot.tree.command(name="deploy", description="Create a new LXC VPS (Admin only)")
@app_commands.describe(ram="RAM in GB", cpu="CPU cores", disk="Disk space in GB", user="The user to create VPS for", os_type="Operating system type")
@app_commands.choices(os_type=[
    app_commands.Choice(name="Ubuntu 22.04", value="ubuntu"),
    app_commands.Choice(name="Debian 11", value="debian"),
    app_commands.Choice(name="Alpine Linux", value="alpine"),
    app_commands.Choice(name="CentOS 8", value="centos"),
    app_commands.Choice(name="Fedora", value="fedora")
])
@app_commands.check(is_admin_interaction)
async def slash_deploy(interaction: discord.Interaction, ram: int, cpu: int, disk: int, user: discord.User, os_type: str = "ubuntu"):
    user_id = user.id
    
    # Check if user has reached VPS limit
    vps_count = await get_user_vps_count(user_id)
    if vps_count >= MAX_VPS_PER_USER:
        await interaction.response.send_message(f"This user has reached the maximum VPS limit of {MAX_VPS_PER_USER}.")
        return
    
    # Check if total containers limit is reached
    try:
        containers_result = subprocess.run(["lxc-list"], capture_output=True, text=True)
        containers = len([line for line in containers_result.stdout.split('\n') if line.strip()])
        
        if containers >= MAX_CONTAINERS:
            await interaction.response.send_message(f"The maximum number of containers ({MAX_CONTAINERS}) has been reached.")
            return
    except Exception as e:
        logger.error(f"Failed to check container count: {e}")
        await interaction.response.send_message(f"Failed to check container count: {str(e)}")
        return
    
    # Create LXC container
    vps_info = await create_lxc_container(user_id, ram, cpu, disk, os_type)
    
    if not vps_info:
        await interaction.response.send_message("Failed to create VPS. Please check the logs.")
        return
    
    # Send DM to user with VPS details
    embed = discord.Embed(
        title="🎉 LXC VPS Creation Successful",
        color=discord.Color.green()
    )
    
    embed.add_field(name="VPS ID", value=vps_info["id"], inline=True)
    embed.add_field(name="Container Name", value=vps_info["container_name"], inline=True)
    embed.add_field(name="Container ID", value=vps_info["container_id"], inline=True)
    embed.add_field(name="OS Type", value=vps_info["os_type"], inline=True)
    embed.add_field(name="Memory", value=f"{vps_info['ram']} GB", inline=True)
    embed.add_field(name="CPU", value=f"{vps_info['cpu']} cores", inline=True)
    embed.add_field(name="Disk", value=f"{vps_info['disk']} GB", inline=True)
    embed.add_field(name="Username", value=vps_info["username"], inline=True)
    embed.add_field(name="Password", value=f"||{vps_info['password']}||", inline=True)
    embed.add_field(name="IP Address", value=vps_info["ip_address"], inline=True)
    embed.add_field(name="SSH Port", value=vps_info["ssh_port"], inline=True)
    embed.add_field(name="SSH Access", value=f"```ssh {vps_info['username']}@{vps_info['ip_address']} -p {vps_info['ssh_port']}```", inline=False)
    
    try:
        await user.send(embed=embed)
        await interaction.response.send_message(f"LXC VPS created successfully for {user.mention}. Details have been sent via DM.")
        await log_activity(interaction.user.id, "DEPLOY_LXC_VPS", f"Deployed LXC VPS #{vps_info['id']} for {user.name}")
    except discord.Forbidden:
        await interaction.response.send_message(f"LXC VPS created successfully for {user.mention}, but I couldn't send them a DM.")

@bot.tree.command(name="delete-vps", description="Delete a VPS (Admin only)")
@app_commands.describe(vps_id="The ID of the VPS to delete")
@app_commands.check(is_admin_interaction)
async def slash_delete_vps(interaction: discord.Interaction, vps_id: int):
    success = await delete_lxc_container(vps_id)
    
    if success:
        await interaction.response.send_message(f"LXC VPS #{vps_id} has been deleted.")
        await log_activity(interaction.user.id, "DELETE_LXC_VPS", f"Deleted LXC VPS #{vps_id}")
    else:
        await interaction.response.send_message(f"Failed to delete LXC VPS #{vps_id}.")

@bot.tree.command(name="stop-vps", description="Stop a VPS (Admin only)")
@app_commands.describe(vps_id="The ID of the VPS to stop")
@app_commands.check(is_admin_interaction)
async def slash_stop_vps(interaction: discord.Interaction, vps_id: int):
    try:
        async with aiosqlite.connect('chunkhost_lxc.db') as db:
            cursor = await db.execute('SELECT container_name FROM vps WHERE id = ?', (vps_id,))
            result = await cursor.fetchone()
        
        if not result:
            await interaction.response.send_message("VPS not found.")
            return
        
        container_name = result[0]
        subprocess.run(["lxc-stop", "-n", container_name], check=True)
        
        await db.execute('UPDATE vps SET status = "stopped" WHERE id = ?', (vps_id,))
        await db.commit()
        
        await interaction.response.send_message(f"LXC VPS #{vps_id} has been stopped.")
        await log_activity(interaction.user.id, "STOP_LXC_VPS", f"Stopped LXC VPS #{vps_id}")
    except Exception as e:
        logger.error(f"Failed to stop VPS: {e}")
        await interaction.response.send_message(f"Failed to stop VPS: {str(e)}")

@bot.tree.command(name="start-vps", description="Start a VPS (Admin only)")
@app_commands.describe(vps_id="The ID of the VPS to start")
@app_commands.check(is_admin_interaction)
async def slash_start_vps(interaction: discord.Interaction, vps_id: int):
    try:
        async with aiosqlite.connect('chunkhost_lxc.db') as db:
            cursor = await db.execute('SELECT container_name FROM vps WHERE id = ?', (vps_id,))
            result = await cursor.fetchone()
        
        if not result:
            await interaction.response.send_message("VPS not found.")
            return
        
        container_name = result[0]
        subprocess.run(["lxc-start", "-n", container_name], check=True)
        
        await db.execute('UPDATE vps SET status = "running" WHERE id = ?', (vps_id,))
        await db.commit()
        
        await interaction.response.send_message(f"LXC VPS #{vps_id} has been started.")
        await log_activity(interaction.user.id, "START_LXC_VPS", f"Started LXC VPS #{vps_id}")
    except Exception as e:
        logger.error(f"Failed to start VPS: {e}")
        await interaction.response.send_message(f"Failed to start VPS: {str(e)}")

@bot.tree.command(name="restart-vps", description="Restart a VPS (Admin only)")
@app_commands.describe(vps_id="The ID of the VPS to restart")
@app_commands.check(is_admin_interaction)
async def slash_restart_vps(interaction: discord.Interaction, vps_id: int):
    try:
        async with aiosqlite.connect('chunkhost_lxc.db') as db:
            cursor = await db.execute('SELECT container_name FROM vps WHERE id = ?', (vps_id,))
            result = await cursor.fetchone()
        
        if not result:
            await interaction.response.send_message("VPS not found.")
            return
        
        container_name = result[0]
        subprocess.run(["lxc-stop", "-n", container_name], check=True)
        subprocess.run(["lxc-start", "-n", container_name], check=True)
        
        await interaction.response.send_message(f"LXC VPS #{vps_id} has been restarted.")
        await log_activity(interaction.user.id, "RESTART_LXC_VPS", f"Restarted LXC VPS #{vps_id}")
    except Exception as e:
        logger.error(f"Failed to restart VPS: {e}")
        await interaction.response.send_message(f"Failed to restart VPS: {str(e)}")

@bot.tree.command(name="freeze-vps", description="Freeze a VPS (Admin only)")
@app_commands.describe(vps_id="The ID of the VPS to freeze")
@app_commands.check(is_admin_interaction)
async def slash_freeze_vps(interaction: discord.Interaction, vps_id: int):
    try:
        async with aiosqlite.connect('chunkhost_lxc.db') as db:
            cursor = await db.execute('SELECT container_name FROM vps WHERE id = ?', (vps_id,))
            result = await cursor.fetchone()
        
        if not result:
            await interaction.response.send_message("VPS not found.")
            return
        
        container_name = result[0]
        subprocess.run(["lxc-freeze", "-n", container_name], check=True)
        
        await db.execute('UPDATE vps SET status = "frozen" WHERE id = ?', (vps_id,))
        await db.commit()
        
        await interaction.response.send_message(f"LXC VPS #{vps_id} has been frozen.")
        await log_activity(interaction.user.id, "FREEZE_LXC_VPS", f"Froze LXC VPS #{vps_id}")
    except Exception as e:
        logger.error(f"Failed to freeze VPS: {e}")
        await interaction.response.send_message(f"Failed to freeze VPS: {str(e)}")

@bot.tree.command(name="unfreeze-vps", description="Unfreeze a VPS (Admin only)")
@app_commands.describe(vps_id="The ID of the VPS to unfreeze")
@app_commands.check(is_admin_interaction)
async def slash_unfreeze_vps(interaction: discord.Interaction, vps_id: int):
    try:
        async with aiosqlite.connect('chunkhost_lxc.db') as db:
            cursor = await db.execute('SELECT container_name FROM vps WHERE id = ?', (vps_id,))
            result = await cursor.fetchone()
        
        if not result:
            await interaction.response.send_message("VPS not found.")
            return
        
        container_name = result[0]
        subprocess.run(["lxc-unfreeze", "-n", container_name], check=True)
        
        await db.execute('UPDATE vps SET status = "running" WHERE id = ?', (vps_id,))
        await db.commit()
        
        await interaction.response.send_message(f"LXC VPS #{vps_id} has been unfrozen.")
        await log_activity(interaction.user.id, "UNFREEZE_LXC_VPS", f"Unfroze LXC VPS #{vps_id}")
    except Exception as e:
        logger.error(f"Failed to unfreeze VPS: {e}")
        await interaction.response.send_message(f"Failed to unfreeze VPS: {str(e)}")

@bot.tree.command(name="upgrade-vps", description="Upgrade VPS resources (Admin only)")
@app_commands.describe(vps_id="The ID of the VPS", ram="New RAM in GB", cpu="New CPU cores", disk="New disk space in GB")
@app_commands.check(is_admin_interaction)
async def slash_upgrade_vps(interaction: discord.Interaction, vps_id: int, ram: int, cpu: int, disk: int):
    try:
        async with aiosqlite.connect('chunkhost_lxc.db') as db:
            cursor = await db.execute('SELECT * FROM vps WHERE id = ?', (vps_id,))
            vps = await cursor.fetchone()
        
        if not vps:
            await interaction.response.send_message("VPS not found.")
            return
        
        container_name = vps[2]
        
        # Update container configuration (simplified)
        config_update = f"""
            lxc config set {container_name} limits.memory {ram * 1024}
            lxc config set {container_name} limits.cpu {cpu}
        """
        
        subprocess.run(config_update, shell=True, check=True)
        
        # Update database
        await db.execute(
            'UPDATE vps SET ram = ?, cpu = ?, disk = ? WHERE id = ?',
            (ram, cpu, disk, vps_id)
        )
        await db.commit()
        
        await interaction.response.send_message(f"LXC VPS #{vps_id} resources have been updated to {ram}GB RAM, {cpu} CPU cores, {disk}GB disk.")
        await log_activity(interaction.user.id, "UPGRADE_LXC_VPS", f"Upgraded LXC VPS #{vps_id} to {ram}GB RAM, {cpu} CPU, {disk}GB disk")
    except Exception as e:
        logger.error(f"Failed to upgrade VPS: {e}")
        await interaction.response.send_message(f"Failed to upgrade VPS: {str(e)}")

@bot.tree.command(name="list-containers", description="List all LXC containers (Admin only)")
@app_commands.check(is_admin_interaction)
async def slash_list_containers(interaction: discord.Interaction):
    try:
        containers_result = subprocess.run(["lxc-list"], capture_output=True, text=True)
        containers = containers_result.stdout.strip().split('\n')
        
        embed = discord.Embed(
            title="LXC Containers",
            description=f"Total containers: {len(containers)}",
            color=discord.Color.blue()
        )
        
        for container in containers[:25]:  # Limit to 25 to avoid embed size limit
            if container.strip():
                embed.add_field(
                    name=container.strip(),
                    value="Active",
                    inline=False
                )
        
        if len(containers) > 25:
            embed.set_footer(text=f"Showing 25 of {len(containers)} containers")
        
        await interaction.response.send_message(embed=embed)
    except Exception as e:
        logger.error(f"Failed to list containers: {e}")
        await interaction.response.send_message(f"Failed to list containers: {str(e)}")

@bot.tree.command(name="system-stats", description="Show system statistics (Admin only)")
@app_commands.check(is_admin_interaction)
async def slash_system_stats(interaction: discord.Interaction):
    try:
        # Get system statistics
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Network stats
        network = psutil.net_io_counters()
        
        # Process count
        process_count = len(psutil.pids())
        
        # Boot time
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        
        # LXC stats
        lxc_containers = subprocess.run(["lxc-list"], capture_output=True, text=True)
        container_count = len([line for line in lxc_containers.stdout.split('\n') if line.strip()])
        
        embed = discord.Embed(
            title="System Statistics",
            color=discord.Color.green()
        )
        
        embed.add_field(name="CPU Usage", value=f"{cpu_percent}%", inline=True)
        embed.add_field(name="Memory Usage", value=f"{memory.percent}%", inline=True)
        embed.add_field(name="Disk Usage", value=f"{disk.percent}%", inline=True)
        embed.add_field(name="LXC Containers", value=container_count, inline=True)
        embed.add_field(name="Total Memory", value=f"{memory.total / (1024**3):.2f} GB", inline=True)
        embed.add_field(name="Available Memory", value=f"{memory.available / (1024**3):.2f} GB", inline=True)
        embed.add_field(name="Used Memory", value=f"{memory.used / (1024**3):.2f} GB", inline=True)
        embed.add_field(name="Total Disk", value=f"{disk.total / (1024**3):.2f} GB", inline=True)
        embed.add_field(name="Free Disk", value=f"{disk.free / (1024**3):.2f} GB", inline=True)
        embed.add_field(name="Used Disk", value=f"{disk.used / (1024**3):.2f} GB", inline=True)
        embed.add_field(name="Network Sent", value=f"{network.bytes_sent / (1024**2):.2f} MB", inline=True)
        embed.add_field(name="Network Received", value=f"{network.bytes_recv / (1024**2):.2f} MB", inline=True)
        embed.add_field(name="Process Count", value=process_count, inline=True)
        embed.add_field(name="System Uptime", value=str(datetime.now() - boot_time).split('.')[0], inline=True)
        embed.add_field(name="Boot Time", value=boot_time.strftime("%Y-%m-%d %H:%M:%S"), inline=True)
        
        await interaction.response.send_message(embed=embed)
    except Exception as e:
        logger.error(f"Failed to get system stats: {e}")
        await interaction.response.send_message(f"Failed to get system stats: {str(e)}")

@bot.tree.command(name="exec-command", description="Execute command in VPS (Admin only)")
@app_commands.describe(vps_id="The ID of the VPS", command="Command to execute")
@app_commands.check(is_admin_interaction)
async def slash_exec_command(interaction: discord.Interaction, vps_id: int, command: str):
    try:
        async with aiosqlite.connect('chunkhost_lxc.db') as db:
            cursor = await db.execute('SELECT container_name FROM vps WHERE id = ?', (vps_id,))
            result = await cursor.fetchone()
        
        if not result:
            await interaction.response.send_message("VPS not found.")
            return
        
        container_name = result[0]
        
        # Execute command
        exec_result = subprocess.run(
            ["lxc-attach", "-n", container_name, "--"] + command.split(),
            capture_output=True, text=True
        )
        
        embed = discord.Embed(
            title=f"Command Execution - VPS #{vps_id}",
            color=discord.Color.blue()
        )
        
        embed.add_field(name="Command", value=f"```{command}```", inline=False)
        embed.add_field(name="Output", value=f"```{exec_result.stdout[:1000]}```", inline=False)
        
        if exec_result.stderr:
            embed.add_field(name="Error", value=f"```{exec_result.stderr[:500]}```", inline=False)
        
        await interaction.response.send_message(embed=embed)
        await log_activity(interaction.user.id, "EXEC_COMMAND", f"Executed '{command}' on VPS #{vps_id}")
    except Exception as e:
        logger.error(f"Failed to execute command: {e}")
        await interaction.response.send_message(f"Failed to execute command: {str(e)}")

@bot.tree.command(name="install-package", description="Install package on VPS (Admin only)")
@app_commands.describe(vps_id="The ID of the VPS", package_name="Name of the package to install")
@app_commands.check(is_admin_interaction)
async def slash_install_package(interaction: discord.Interaction, vps_id: int, package_name: str):
    try:
        async with aiosqlite.connect('chunkhost_lxc.db') as db:
            cursor = await db.execute('SELECT * FROM vps WHERE id = ?', (vps_id,))
            vps = await cursor.fetchone()
        
        if not vps:
            await interaction.response.send_message("VPS not found.")
            return
        
        container_name = vps[2]
        
        # Install package based on OS type
        if vps[8] in ["ubuntu", "debian"]:
            install_cmd = ["lxc-attach", "-n", container_name, "--", "apt-get", "update", "&&", "apt-get", "install", "-y", package_name]
        elif vps[8] == "alpine":
            install_cmd = ["lxc-attach", "-n", container_name, "--", "apk", "update", "&&", "apk", "add", package_name]
        elif vps[8] in ["centos", "fedora"]:
            install_cmd = ["lxc-attach", "-n", container_name, "--", "yum", "update", "-y", "&&", "yum", "install", "-y", package_name]
        else:
            install_cmd = ["lxc-attach", "-n", container_name, "--", "echo", "'Unsupported OS for package installation'"]
        
        # Install package
        exec_result = subprocess.run(install_cmd, capture_output=True, text=True)
        
        embed = discord.Embed(
            title=f"Package Installation: {package_name}",
            color=discord.Color.blue()
        )
        
        if exec_result.returncode == 0:
            embed.add_field(name="Status", value="Package installed successfully", inline=False)
        else:
            embed.add_field(name="Status", value="Failed to install package", inline=False)
            embed.add_field(name="Error", value=exec_result.stderr[:500], inline=False)
        
        await interaction.response.send_message(embed=embed)
        await log_activity(interaction.user.id, "INSTALL_PACKAGE", f"Installed {package_name} on VPS #{vps_id}")
    except Exception as e:
        logger.error(f"Failed to install package: {e}")
        await interaction.response.send_message(f"Failed to install package: {str(e)}")

@bot.tree.command(name="cleanup", description="Cleanup unused resources (Admin only)")
@app_commands.check(is_admin_interaction)
async def slash_cleanup(interaction: discord.Interaction):
    try:
        cleanup_results = {}
        
        # Cleanup LXC containers
        stopped_containers_result = subprocess.run(["lxc-list"], capture_output=True, text=True)
        stopped_containers = []
        
        for line in stopped_containers_result.stdout.split('\n'):
            if line.strip() and "STOPPED" in line.upper():
                container_name = line.split()[0]
                try:
                    subprocess.run(["lxc-delete", "-n", container_name], check=True)
                    stopped_containers.append(container_name)
                except:
                    pass
        
        cleanup_results['Stopped Containers'] = len(stopped_containers)
        
        # Cleanup unused images
        try:
            unused_images_result = subprocess.run(["lxc-image", "list"], capture_output=True, text=True)
            unused_images = len([line for line in unused_images_result.stdout.split('\n') if line.strip()])
            cleanup_results['Unused Images'] = unused_images
        except:
            cleanup_results['Unused Images'] = "Failed"
        
        embed = discord.Embed(
            title="LXC Cleanup Results",
            color=discord.Color.green()
        )
        
        for resource_type, count in cleanup_results.items():
            embed.add_field(name=resource_type, value=str(count), inline=True)
        
        await interaction.response.send_message(embed=embed)
        await log_activity(interaction.user.id, "CLEANUP", f"Cleaned up unused LXC resources")
    except Exception as e:
        logger.error(f"Failed to cleanup: {e}")
        await interaction.response.send_message(f"Failed to cleanup: {str(e)}")

# ==================== PREFIX COMMANDS ====================

# Create wrapper functions for prefix commands
async def handle_deploy(ctx, ram: int, cpu: int, disk: int, user: discord.User, os_type: str = "ubuntu"):
    user_id = user.id
    
    # Check if user has reached VPS limit
    vps_count = await get_user_vps_count(user_id)
    if vps_count >= MAX_VPS_PER_USER:
        await ctx.send(f"This user has reached the maximum VPS limit of {MAX_VPS_PER_USER}.")
        return
    
    # Check if total containers limit is reached
    try:
        containers_result = subprocess.run(["lxc-list"], capture_output=True, text=True)
        containers = len([line for line in containers_result.stdout.split('\n') if line.strip()])
        
        if containers >= MAX_CONTAINERS:
            await ctx.send(f"The maximum number of containers ({MAX_CONTAINERS}) has been reached.")
            return
    except Exception as e:
        logger.error(f"Failed to check container count: {e}")
        await ctx.send(f"Failed to check container count: {str(e)}")
        return
    
    # Create LXC container
    vps_info = await create_lxc_container(user_id, ram, cpu, disk, os_type)
    
    if not vps_info:
        await ctx.send("Failed to create VPS. Please check the logs.")
        return
    
    # Send DM to user with VPS details
    embed = discord.Embed(
        title="🎉 LXC VPS Creation Successful",
        color=discord.Color.green()
    )
    
    embed.add_field(name="VPS ID", value=vps_info["id"], inline=True)
    embed.add_field(name="Container Name", value=vps_info["container_name"], inline=True)
    embed.add_field(name="Container ID", value=vps_info["container_id"], inline=True)
    embed.add_field(name="OS Type", value=vps_info["os_type"], inline=True)
    embed.add_field(name="Memory", value=f"{vps_info['ram']} GB", inline=True)
    embed.add_field(name="CPU", value=f"{vps_info['cpu']} cores", inline=True)
    embed.add_field(name="Disk", value=f"{vps_info['disk']} GB", inline=True)
    embed.add_field(name="Username", value=vps_info["username"], inline=True)
    embed.add_field(name="Password", value=f"||{vps_info['password']}||", inline=True)
    embed.add_field(name="IP Address", value=vps_info["ip_address"], inline=True)
    embed.add_field(name="SSH Port", value=vps_info["ssh_port"], inline=True)
    embed.add_field(name="SSH Access", value=f"```ssh {vps_info['username']}@{vps_info['ip_address']} -p {vps_info['ssh_port']}```", inline=False)
    
    try:
        await user.send(embed=embed)
        await ctx.send(f"LXC VPS created successfully for {user.mention}. Details have been sent via DM.")
        await log_activity(ctx.author.id, "DEPLOY_LXC_VPS", f"Deployed LXC VPS #{vps_info['id']} for {user.name}")
    except discord.Forbidden:
        await ctx.send(f"LXC VPS created successfully for {user.mention}, but I couldn't send them a DM.")

async def handle_delete_vps(ctx, vps_id: int):
    success = await delete_lxc_container(vps_id)
    
    if success:
        await ctx.send(f"LXC VPS #{vps_id} has been deleted.")
        await log_activity(ctx.author.id, "DELETE_LXC_VPS", f"Deleted LXC VPS #{vps_id}")
    else:
        await ctx.send(f"Failed to delete LXC VPS #{vps_id}.")

async def handle_stop_vps(ctx, vps_id: int):
    try:
        async with aiosqlite.connect('chunkhost_lxc.db') as db:
            cursor = await db.execute('SELECT container_name FROM vps WHERE id = ?', (vps_id,))
            result = await cursor.fetchone()
        
        if not result:
            await ctx.send("VPS not found.")
            return
        
        container_name = result[0]
        subprocess.run(["lxc-stop", "-n", container_name], check=True)
        
        await db.execute('UPDATE vps SET status = "stopped" WHERE id = ?', (vps_id,))
        await db.commit()
        
        await ctx.send(f"LXC VPS #{vps_id} has been stopped.")
        await log_activity(ctx.author.id, "STOP_LXC_VPS", f"Stopped LXC VPS #{vps_id}")
    except Exception as e:
        logger.error(f"Failed to stop VPS: {e}")
        await ctx.send(f"Failed to stop VPS: {str(e)}")

async def handle_start_vps(ctx, vps_id: int):
    try:
        async with aiosqlite.connect('chunkhost_lxc.db') as db:
            cursor = await db.execute('SELECT container_name FROM vps WHERE id = ?', (vps_id,))
            result = await cursor.fetchone()
        
        if not result:
            await ctx.send("VPS not found.")
            return
        
        container_name = result[0]
        subprocess.run(["lxc-start", "-n", container_name], check=True)
        
        await db.execute('UPDATE vps SET status = "running" WHERE id = ?', (vps_id,))
        await db.commit()
        
        await ctx.send(f"LXC VPS #{vps_id} has been started.")
        await log_activity(ctx.author.id, "START_LXC_VPS", f"Started LXC VPS #{vps_id}")
    except Exception as e:
        logger.error(f"Failed to start VPS: {e}")
        await ctx.send(f"Failed to start VPS: {str(e)}")

async def handle_restart_vps(ctx, vps_id: int):
    try:
        async with aiosqlite.connect('chunkhost_lxc.db') as db:
            cursor = await db.execute('SELECT container_name FROM vps WHERE id = ?', (vps_id,))
            result = await cursor.fetchone()
        
        if not result:
            await ctx.send("VPS not found.")
            return
        
        container_name = result[0]
        subprocess.run(["lxc-stop", "-n", container_name], check=True)
        subprocess.run(["lxc-start", "-n", container_name], check=True)
        
        await ctx.send(f"LXC VPS #{vps_id} has been restarted.")
        await log_activity(ctx.author.id, "RESTART_LXC_VPS", f"Restarted LXC VPS #{vps_id}")
    except Exception as e:
        logger.error(f"Failed to restart VPS: {e}")
        await ctx.send(f"Failed to restart VPS: {str(e)}")

async def handle_freeze_vps(ctx, vps_id: int):
    try:
        async with aiosqlite.connect('chunkhost_lxc.db') as db:
            cursor = await db.execute('SELECT container_name FROM vps WHERE id = ?', (vps_id,))
            result = await cursor.fetchone()
        
        if not result:
            await ctx.send("VPS not found.")
            return
        
        container_name = result[0]
        subprocess.run(["lxc-freeze", "-n", container_name], check=True)
        
        await db.execute('UPDATE vps SET status = "frozen" WHERE id = ?', (vps_id,))
        await db.commit()
        
        await ctx.send(f"LXC VPS #{vps_id} has been frozen.")
        await log_activity(ctx.author.id, "FREEZE_LXC_VPS", f"Froze LXC VPS #{vps_id}")
    except Exception as e:
        logger.error(f"Failed to freeze VPS: {e}")
        await ctx.send(f"Failed to freeze VPS: {str(e)}")

async def handle_unfreeze_vps(ctx, vps_id: int):
    try:
        async with aiosqlite.connect('chunkhost_lxc.db') as db:
            cursor = await db.execute('SELECT container_name FROM vps WHERE id = ?', (vps_id,))
            result = await cursor.fetchone()
        
        if not result:
            await ctx.send("VPS not found.")
            return
        
        container_name = result[0]
        subprocess.run(["lxc-unfreeze", "-n", container_name], check=True)
        
        await db.execute('UPDATE vps SET status = "running" WHERE id = ?', (vps_id,))
        await db.commit()
        
        await ctx.send(f"LXC VPS #{vps_id} has been unfrozen.")
        await log_activity(ctx.author.id, "UNFREEZE_LXC_VPS", f"Unfroze LXC VPS #{vps_id}")
    except Exception as e:
        logger.error(f"Failed to unfreeze VPS: {e}")
        await ctx.send(f"Failed to unfreeze VPS: {str(e)}")

async def handle_upgrade_vps(ctx, vps_id: int, ram: int, cpu: int, disk: int):
    try:
        async with aiosqlite.connect('chunkhost_lxc.db') as db:
            cursor = await db.execute('SELECT * FROM vps WHERE id = ?', (vps_id,))
            vps = await cursor.fetchone()
        
        if not vps:
            await ctx.send("VPS not found.")
            return
        
        container_name = vps[2]
        
        # Update container configuration (simplified)
        config_update = f"""
            lxc config set {container_name} limits.memory {ram * 1024}
            lxc config set {container_name} limits.cpu {cpu}
        """
        
        subprocess.run(config_update, shell=True, check=True)
        
        # Update database
        await db.execute(
            'UPDATE vps SET ram = ?, cpu = ?, disk = ? WHERE id = ?',
            (ram, cpu, disk, vps_id)
        )
        await db.commit()
        
        await ctx.send(f"LXC VPS #{vps_id} resources have been updated to {ram}GB RAM, {cpu} CPU cores, {disk}GB disk.")
        await log_activity(ctx.author.id, "UPGRADE_LXC_VPS", f"Upgraded LXC VPS #{vps_id} to {ram}GB RAM, {cpu} CPU, {disk}GB disk")
    except Exception as e:
        logger.error(f"Failed to upgrade VPS: {e}")
        await ctx.send(f"Failed to upgrade VPS: {str(e)}")

async def handle_list_containers(ctx):
    try:
        containers_result = subprocess.run(["lxc-list"], capture_output=True, text=True)
        containers = containers_result.stdout.strip().split('\n')
        
        embed = discord.Embed(
            title="LXC Containers",
            description=f"Total containers: {len(containers)}",
            color=discord.Color.blue()
        )
        
        for container in containers[:25]:  # Limit to 25 to avoid embed size limit
            if container.strip():
                embed.add_field(
                    name=container.strip(),
                    value="Active",
                    inline=False
                )
        
        if len(containers) > 25:
            embed.set_footer(text=f"Showing 25 of {len(containers)} containers")
        
        await ctx.send(embed=embed)
    except Exception as e:
        logger.error(f"Failed to list containers: {e}")
        await ctx.send(f"Failed to list containers: {str(e)}")

async def handle_system_stats(ctx):
    try:
        # Get system statistics
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Network stats
        network = psutil.net_io_counters()
        
        # Process count
        process_count = len(psutil.pids())
        
        # Boot time
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        
        # LXC stats
        lxc_containers = subprocess.run(["lxc-list"], capture_output=True, text=True)
        container_count = len([line for line in lxc_containers.stdout.split('\n') if line.strip()])
        
        embed = discord.Embed(
            title="System Statistics",
            color=discord.Color.green()
        )
        
        embed.add_field(name="CPU Usage", value=f"{cpu_percent}%", inline=True)
        embed.add_field(name="Memory Usage", value=f"{memory.percent}%", inline=True)
        embed.add_field(name="Disk Usage", value=f"{disk.percent}%", inline=True)
        embed.add_field(name="LXC Containers", value=container_count, inline=True)
        embed.add_field(name="Total Memory", value=f"{memory.total / (1024**3):.2f} GB", inline=True)
        embed.add_field(name="Available Memory", value=f"{memory.available / (1024**3):.2f} GB", inline=True)
        embed.add_field(name="Used Memory", value=f"{memory.used / (1024**3):.2f} GB", inline=True)
        embed.add_field(name="Total Disk", value=f"{disk.total / (1024**3):.2f} GB", inline=True)
        embed.add_field(name="Free Disk", value=f"{disk.free / (1024**3):.2f} GB", inline=True)
        embed.add_field(name="Used Disk", value=f"{disk.used / (1024**3):.2f} GB", inline=True)
        embed.add_field(name="Network Sent", value=f"{network.bytes_sent / (1024**2):.2f} MB", inline=True)
        embed.add_field(name="Network Received", value=f"{network.bytes_recv / (1024**2):.2f} MB", inline=True)
        embed.add_field(name="Process Count", value=process_count, inline=True)
        embed.add_field(name="System Uptime", value=str(datetime.now() - boot_time).split('.')[0], inline=True)
        embed.add_field(name="Boot Time", value=boot_time.strftime("%Y-%m-%d %H:%M:%S"), inline=True)
        
        await ctx.send(embed=embed)
    except Exception as e:
        logger.error(f"Failed to get system stats: {e}")
        await ctx.send(f"Failed to get system stats: {str(e)}")

async def handle_exec_command(ctx, vps_id: int, *, command: str):
    try:
        async with aiosqlite.connect('chunkhost_lxc.db') as db:
            cursor = await db.execute('SELECT container_name FROM vps WHERE id = ?', (vps_id,))
            result = await cursor.fetchone()
        
        if not result:
            await ctx.send("VPS not found.")
            return
        
        container_name = result[0]
        
        # Execute command
        exec_result = subprocess.run(
            ["lxc-attach", "-n", container_name, "--"] + command.split(),
            capture_output=True, text=True
        )
        
        embed = discord.Embed(
            title=f"Command Execution - VPS #{vps_id}",
            color=discord.Color.blue()
        )
        
        embed.add_field(name="Command", value=f"```{command}```", inline=False)
        embed.add_field(name="Output", value=f"```{exec_result.stdout[:1000]}```", inline=False)
        
        if exec_result.stderr:
            embed.add_field(name="Error", value=f"```{exec_result.stderr[:500]}```", inline=False)
        
        await ctx.send(embed=embed)
        await log_activity(ctx.author.id, "EXEC_COMMAND", f"Executed '{command}' on VPS #{vps_id}")
    except Exception as e:
        logger.error(f"Failed to execute command: {e}")
        await ctx.send(f"Failed to execute command: {str(e)}")

async def handle_install_package(ctx, vps_id: int, package_name: str):
    try:
        async with aiosqlite.connect('chunkhost_lxc.db') as db:
            cursor = await db.execute('SELECT * FROM vps WHERE id = ?', (vps_id,))
            vps = await cursor.fetchone()
        
        if not vps:
            await ctx.send("VPS not found.")
            return
        
        container_name = vps[2]
        
        # Install package based on OS type
        if vps[8] in ["ubuntu", "debian"]:
            install_cmd = ["lxc-attach", "-n", container_name, "--", "apt-get", "update", "&&", "apt-get", "install", "-y", package_name]
        elif vps[8] == "alpine":
            install_cmd = ["lxc-attach", "-n", container_name, "--", "apk", "update", "&&", "apk", "add", package_name]
        elif vps[8] in ["centos", "fedora"]:
            install_cmd = ["lxc-attach", "-n", container_name, "--", "yum", "update", "-y", "&&", "yum", "install", "-y", package_name]
        else:
            install_cmd = ["lxc-attach", "-n", container_name, "--", "echo", "'Unsupported OS for package installation'"]
        
        # Install package
        exec_result = subprocess.run(install_cmd, capture_output=True, text=True)
        
        embed = discord.Embed(
            title=f"Package Installation: {package_name}",
            color=discord.Color.blue()
        )
        
        if exec_result.returncode == 0:
            embed.add_field(name="Status", value="Package installed successfully", inline=False)
        else:
            embed.add_field(name="Status", value="Failed to install package", inline=False)
            embed.add_field(name="Error", value=exec_result.stderr[:500], inline=False)
        
        await ctx.send(embed=embed)
        await log_activity(ctx.author.id, "INSTALL_PACKAGE", f"Installed {package_name} on VPS #{vps_id}")
    except Exception as e:
        logger.error(f"Failed to install package: {e}")
        await ctx.send(f"Failed to install package: {str(e)}")

async def handle_cleanup(ctx):
    try:
        cleanup_results = {}
        
        # Cleanup LXC containers
        stopped_containers_result = subprocess.run(["lxc-list"], capture_output=True, text=True)
        stopped_containers = []
        
        for line in stopped_containers_result.stdout.split('\n'):
            if line.strip() and "STOPPED" in line.upper():
                container_name = line.split()[0]
                try:
                    subprocess.run(["lxc-delete", "-n", container_name], check=True)
                    stopped_containers.append(container_name)
                except:
                    pass
        
        cleanup_results['Stopped Containers'] = len(stopped_containers)
        
        # Cleanup unused images
        try:
            unused_images_result = subprocess.run(["lxc-image", "list"], capture_output=True, text=True)
            unused_images = len([line for line in unused_images_result.stdout.split('\n') if line.strip()])
            cleanup_results['Unused Images'] = unused_images
        except:
            cleanup_results['Unused Images'] = "Failed"
        
        embed = discord.Embed(
            title="LXC Cleanup Results",
            color=discord.Color.green()
        )
        
        for resource_type, count in cleanup_results.items():
            embed.add_field(name=resource_type, value=str(count), inline=True)
        
        await ctx.send(embed=embed)
        await log_activity(ctx.author.id, "CLEANUP", f"Cleaned up unused LXC resources")
    except Exception as e:
        logger.error(f"Failed to cleanup: {e}")
        await ctx.send(f"Failed to cleanup: {str(e)}")

# Prefix command definitions
@bot.command(name="help", help="Show all commands")
async def prefix_help(ctx):
    await slash_help(ctx)

@bot.command(name="myvps", help="Show your LXC VPS instances")
async def prefix_myvps(ctx):
    await slash_myvps(ctx)

@bot.command(name="status", help="Show LXC VPS resource usage")
async def prefix_status(ctx, vps_id: int):
    await slash_status(ctx, vps_id)

@bot.command(name="re-ssh", help="Regenerate SSH access for your VPS")
async def prefix_re_ssh(ctx, vps_id: int):
    await slash_re_ssh(ctx, vps_id)

@bot.command(name="info", help="Show system information")
async def prefix_info(ctx):
    await slash_info(ctx)

@bot.command(name="ping", help="Check bot latency")
async def prefix_ping(ctx):
    await slash_ping(ctx)

@bot.command(name="uptime", help="Show system uptime")
async def prefix_uptime(ctx):
    await slash_uptime(ctx)

@bot.command(name="who-made", help="Bot information")
async def prefix_who_made(ctx):
    await slash_who_made(ctx)

# Admin prefix commands
@bot.command(name="deploy", help="Create a new LXC VPS (Admin only)")
@commands.check(is_admin)
async def prefix_deploy(ctx, ram: int, cpu: int, disk: int, user: discord.User, os_type: str = "ubuntu"):
    await handle_deploy(ctx, ram, cpu, disk, user, os_type)

@bot.command(name="delete-vps", help="Delete a VPS (Admin only)")
@commands.check(is_admin)
async def prefix_delete_vps(ctx, vps_id: int):
    await handle_delete_vps(ctx, vps_id)

@bot.command(name="stop-vps", help="Stop a VPS (Admin only)")
@commands.check(is_admin)
async def prefix_stop_vps(ctx, vps_id: int):
    await handle_stop_vps(ctx, vps_id)

@bot.command(name="start-vps", help="Start a VPS (Admin only)")
@commands.check(is_admin)
async def prefix_start_vps(ctx, vps_id: int):
    await handle_start_vps(ctx, vps_id)

@bot.command(name="restart-vps", help="Restart a VPS (Admin only)")
@commands.check(is_admin)
async def prefix_restart_vps(ctx, vps_id: int):
    await handle_restart_vps(ctx, vps_id)

@bot.command(name="freeze-vps", help="Freeze a VPS (Admin only)")
@commands.check(is_admin)
async def prefix_freeze_vps(ctx, vps_id: int):
    await handle_freeze_vps(ctx, vps_id)

@bot.command(name="unfreeze-vps", help="Unfreeze a VPS (Admin only)")
@commands.check(is_admin)
async def prefix_unfreeze_vps(ctx, vps_id: int):
    await handle_unfreeze_vps(ctx, vps_id)

@bot.command(name="upgrade-vps", help="Upgrade VPS resources (Admin only)")
@commands.check(is_admin)
async def prefix_upgrade_vps(ctx, vps_id: int, ram: int, cpu: int, disk: int):
    await handle_upgrade_vps(ctx, vps_id, ram, cpu, disk)

@bot.command(name="list-containers", help="List all LXC containers (Admin only)")
@commands.check(is_admin)
async def prefix_list_containers(ctx):
    await handle_list_containers(ctx)

@bot.command(name="system-stats", help="Show system statistics (Admin only)")
@commands.check(is_admin)
async def prefix_system_stats(ctx):
    await handle_system_stats(ctx)

@bot.command(name="exec-command", help="Execute command in VPS (Admin only)")
@commands.check(is_admin)
async def prefix_exec_command(ctx, vps_id: int, *, command: str):
    await handle_exec_command(ctx, vps_id, command=command)

@bot.command(name="install-package", help="Install package on VPS (Admin only)")
@commands.check(is_admin)
async def prefix_install_package(ctx, vps_id: int, package_name: str):
    await handle_install_package(ctx, vps_id, package_name)

@bot.command(name="cleanup", help="Cleanup unused resources (Admin only)")
@commands.check(is_admin)
async def prefix_cleanup(ctx):
    await handle_cleanup(ctx)

# Error handling
@bot.tree.error
async def on_slash_command_error(interaction: discord.Interaction, error):
    if isinstance(error, app_commands.MissingPermissions):
        await interaction.response.send_message("You don't have permission to use this command.", ephemeral=True)
    elif isinstance(error, app_commands.CommandOnCooldown):
        await interaction.response.send_message(f"This command is on cooldown. Try again in {error.retry_after:.2f} seconds.", ephemeral=True)
    else:
        logger.error(f"Slash command error: {error}")
        await interaction.response.send_message(f"An error occurred: {str(error)}", ephemeral=True)

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.MissingPermissions):
        await ctx.send("You don't have permission to use this command.")
    elif isinstance(error, commands.CommandOnCooldown):
        await ctx.send(f"This command is on cooldown. Try again in {error.retry_after:.2f} seconds.")
    elif isinstance(error, commands.CommandNotFound):
        pass  # Ignore command not found errors
    else:
        logger.error(f"Prefix command error: {error}")
        await ctx.send(f"An error occurred: {str(error)}")

# Run the bot
if __name__ == "__main__":
    bot.run(TOKEN)
