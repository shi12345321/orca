import asyncio
import os
import discord
import logging
import requests
from discord.ext import commands
from dotenv import load_dotenv
load_dotenv()
TOKEN = os.getenv('DISCORD_TOKEN')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s:%(message)s')
logger = logging.getLogger('discord_bot')
intents = discord.Intents.default()
intents.members = True
intents.guilds = True
intents.message_content = True
intents.reactions = True
bot = commands.Bot(command_prefix='!', intents=intents)
invites = {}

import os


log_channels = {}

quote_channels = {}

from discord.ext import tasks
import aiohttp
import datetime

@bot.event
async def on_ready():
    logger.info(f'Logged in as {bot.user} (ID: {bot.user.id})')
    logger.info('------')
    activity = discord.Game(name="WATCHING ORCA SERVERS")
    await bot.change_presence(status=discord.Status.online, activity=activity)
    
    for guild in bot.guilds:
        invites[guild.id] = await guild.invites()
        logger.debug(f'Cached invites for guild: {guild.name} ({guild.id})')

  

async def send_log_message(bot, guild_id, member, action):
    channel_id = log_channels.get(guild_id)
    if not channel_id:
        logger.warning(f"Log channel is not set for guild {guild_id}. Cannot send log message.")
        return
    channel = bot.get_channel(channel_id)
    if channel is None:
        logger.warning(f"Log channel with ID {channel_id} not found in guild {guild_id}.")
        return
        return
    try:
        embed = discord.Embed(color=discord.Color.dark_red())
        embed.set_author(name="ORCA")
        embed.set_footer(text="Made by Alfie")
        embed.timestamp = discord.utils.utcnow()
        embed.set_thumbnail(url=member.avatar.url if member.avatar else member.default_avatar.url)
        embed.set_image(url="https://cdn.discordapp.com/attachments/1379846639069691965/1381888389850333296/orca2.jpg?ex=6864d6da&is=6863855a&hm=f7ab771cea2f0317ec01a4d3f18e5601e39c23b5079c6382e16957a8a3b62191&")  # Placeholder logo image
        embed.add_field(name="Member", value=f"{member.name}#{member.discriminator}", inline=True)
        embed.add_field(name="ID", value=str(member.id), inline=True)
        embed.add_field(name="Action", value=action, inline=False)
        await channel.send(embed=embed)
    except Exception as e:
        logger.error(f"Failed to send log message: {e}")

@bot.event
async def on_ready():
    logger.info(f'Logged in as {bot.user} (ID: {bot.user.id})')
    logger.info('------')
    activity = discord.Game(name="WATCHING ORCA SERVERS")
    await bot.change_presence(status=discord.Status.online, activity=activity)
    
    for guild in bot.guilds:
        invites[guild.id] = await guild.invites()
        logger.debug(f'Cached invites for guild: {guild.name} ({guild.id})')
async def query_virustotal(url):
    import base64
    import asyncio
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        submit_response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
        if submit_response.status_code not in [200, 201]:
            logger.error(f"Failed to submit URL to VirusTotal: {submit_response.status_code} {submit_response.text}")
            return None
        analysis_id = submit_response.json().get('data', {}).get('id')
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        
        max_retries = 5
        retry_delay = 10  # seconds
        for attempt in range(max_retries):
            url_report = requests.get(analysis_url, headers=headers)
            if url_report.status_code == 200:
                data = url_report.json()
                status = data.get("data", {}).get("attributes", {}).get("status")
                if status == "completed":
                    stats = data.get("data", {}).get("attributes", {}).get("stats", {})
                    return {"stats": stats, "analysis_id": analysis_id}
                else:
                    logger.debug(f"Analysis status: {status}. Retrying in {retry_delay} seconds...")
                    await asyncio.sleep(retry_delay)
            else:
                logger.error(f"Failed to get URL report: {url_report.status_code} {url_report.text}")
                return None
        logger.warning("VirusTotal analysis did not complete in time.")
        return None
    except Exception as e:
        logger.error(f"Error querying VirusTotal: {e}")
        return None
@bot.event
async def on_ready():
    logger.info(f'Logged in as {bot.user} (ID: {bot.user.id})')
    logger.info('------')
    activity = discord.Game(name="ur ass mfcker")
    await bot.change_presence(status=discord.Status.online, activity=activity)
    
    for guild in bot.guilds:
        invites[guild.id] = await guild.invites()
        logger.debug(f'Cached invites for guild: {guild.name} ({guild.id})')
@bot.event
async def on_guild_join(guild):
    invites[guild.id] = await guild.invites()
    logger.debug(f'Cached invites for new guild: {guild.name} ({guild.id})')
@bot.event
async def on_member_join(member):
    logger.debug(f'Member joined: {member} (bot={member.bot})')
    if member.bot:
        try:       
            async for entry in member.guild.audit_logs(limit=5, action=discord.AuditLogAction.bot_add):
                if entry.target.id == member.id:
                    inviter = entry.user
                    logger.info(f'Bot {member} was added by {inviter} (ID: {inviter.id})')
                    bot_member = member.guild.get_member(bot.user.id)
                    inviter_member = member.guild.get_member(inviter.id)
                    if bot_member is None:
                        logger.warning('Bot member not found in guild.')
                    if inviter_member is None:
                        logger.warning('Inviter member not found in guild.')
                    else:
                        logger.info(f'Bot top role: {bot_member.top_role} (position {bot_member.top_role.position})')
                        logger.info(f'Inviter top role: {inviter_member.top_role} (position {inviter_member.top_role.position})')
                        if bot_member.top_role.position <= inviter_member.top_role.position:
                            logger.warning('Bot role is not higher than inviter role. Cannot kick.')
                    try:                    
                        await member.guild.ban(member, reason="Bot added to server - banned automatically")
                        logger.info(f'Banned bot {member} from the server.')              
                        await member.guild.ban(inviter, reason="Added a bot to the server - banned automatically")
                        logger.info(f'Banned inviter {inviter} for adding a bot.')
                    except discord.Forbidden:
                        logger.error(f'Failed to ban {inviter} or bot {member}: Missing Permissions')
                    except Exception as e:
                        logger.error(f'Failed to ban {inviter} or bot {member}: {e}')
                    break
        except Exception as e:
            logger.error(f'Error fetching audit logs: {e}')
    
    await send_log_message(bot, member.guild.id, member, "Member joined")

@bot.event
async def on_member_remove(member):
    logger.debug(f'Member left: {member} (bot={member.bot})')
    await send_log_message(bot, member.guild.id, member, "Member left")

async def scan(ctx, url: str):
    """Scan a URL using VirusTotal"""
    if not VIRUSTOTAL_API_KEY:
        await ctx.send("VirusTotal API key is not set. Please set it in the .env file.")
        return
    await ctx.send(f"Scanning URL: {url}")
    result = await query_virustotal(url)
    if result:
        stats = result.get("stats", {})
        positives = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = sum([v for v in stats.values() if isinstance(v, int)])
        if positives > 0:
            color = discord.Color.red()
            status_emoji = "🛑"
            status_text = "Malicious detections found!"
        elif suspicious > 0:
            color = discord.Color.orange()
            status_emoji = "⚠️"
            status_text = "Suspicious detections found!"
        else:
            color = discord.Color.green()
            status_emoji = "✅"
            status_text = "No malicious detections."
        embed = discord.Embed(
            title=f"Scan results for {url}",
            description=f"{status_emoji} {status_text}",
            color=color
        )
        embed.add_field(name="Malicious detections", value=f"🛑 {positives}", inline=True)
        embed.add_field(name="Suspicious detections", value=f"⚠️ {suspicious}", inline=True)
        embed.add_field(name="Harmless detections", value=f"✅ {harmless}", inline=True)
        embed.add_field(name="Undetected", value=f"❓ {undetected}", inline=True)
        embed.add_field(name="Total engines", value=f"🔍 {total}", inline=True)
        analysis_id = None
        if isinstance(result, dict) and "analysis_id" in result:
            analysis_id = result["analysis_id"]
        if not analysis_id:
            analysis_id = None
        if analysis_id:
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            detailed_report = requests.get(analysis_url, headers={"x-apikey": VIRUSTOTAL_API_KEY})
            if detailed_report.status_code == 200:
                data = detailed_report.json()
                results = data.get("data", {}).get("attributes", {}).get("results", {})
                details_text = ""
                for engine, result in results.items():
                    category = result.get("category", "unknown")
                    if category not in ["malicious", "suspicious"]:
                        continue
                    method = result.get("method", "unknown")
                    engine_name = result.get("engine_name", engine)
                    result_message = result.get("result", "none")
                    details_text += f"**{engine_name}**: {category} (method: {method}) - Result: {result_message}\n"
                if details_text:
                  
                    chunk_size = 1024
                    for i in range(0, len(details_text), chunk_size):
                        chunk = details_text[i:i+chunk_size]
                        if i == 0:
                            embed.add_field(name="Details", value=chunk, inline=False)
                        else:
                            embed.add_field(name=f"Details (cont.)", value=chunk, inline=False)
            else:
                embed.add_field(name="Details", value="Failed to retrieve detailed scan results.", inline=False)
        else:
            embed.add_field(name="Details", value="Analysis ID not found, cannot retrieve detailed scan results.", inline=False)
        await ctx.send(embed=embed)
    else:
        await ctx.send("Failed to retrieve scan results from VirusTotal.")

import aiohttp

async def check_profile_exists(session, url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
    }
    try:
        async with session.head(url, headers=headers, allow_redirects=True) as response:
            logger.debug(f"Checked URL {url} with status {response.status}")
            if response.status in [200, 301, 302, 400, 403, 405, 999]:
                return True
            else:
                return False
    except Exception as e:
        logger.error(f"HEAD request failed for URL {url}: {e}, trying GET request")
        try:
            async with session.get(url, headers=headers, allow_redirects=True) as response:
                logger.debug(f"GET request checked URL {url} with status {response.status}")
                if response.status in [200, 301, 302, 400, 403, 405, 999]:
                    return True
                else:
                    return False
        except Exception as e2:
            logger.error(f"GET request failed for URL {url}: {e2}")
            return False


import re

suspicious_patterns = [
    r"https?://[^\s]*image-logger[^\s]*",
    r"https?://[^\s]*keylogger[^\s]*",
    r"https?://[^\s]*tokengrabber[^\s]*",
    r"https?://[^\s]*grabber[^\s]*",
    r"https?://[^\s]*logger[^\s]*",
]

def contains_suspicious_link(message_content):
    for pattern in suspicious_patterns:
        if re.search(pattern, message_content, re.IGNORECASE):
            return True
    return False

@bot.event
async def on_message(message):
    if message.author == bot.user:
        return

    
    if contains_suspicious_link(message.content):
        logger.warning(f"Suspicious link detected in message from {message.author} in {message.channel}: {message.content}")
        embed = discord.Embed(description=f"Warning: Suspicious link detected from {message.author.mention}!", color=discord.Color.red())
        await message.channel.send(embed=embed)

    
    for attachment in message.attachments:
    
        if contains_suspicious_link(attachment.url):
            logger.warning(f"Suspicious attachment URL detected from {message.author} in {message.channel}: {attachment.url}")
            embed = discord.Embed(description=f"Warning: Suspicious attachment detected from {message.author.mention}!", color=discord.Color.red())
            await message.channel.send(embed=embed)
            break
        
        if contains_suspicious_link(attachment.filename):
            logger.warning(f"Suspicious attachment filename detected from {message.author} in {message.channel}: {attachment.filename}")
            embed = discord.Embed(description=f"Warning: Suspicious attachment detected from {message.author.mention}!", color=discord.Color.red())
            await message.channel.send(embed=embed)
            break

    
    await bot.process_commands(message)

@bot.command(name='scanserver')
@commands.has_permissions(administrator=True)
async def scanserver(ctx, limit: int = 100):
    """Scan recent messages in the server for suspicious links"""
    await ctx.send(f"Scanning the last {limit} messages in this server for suspicious links...")
    suspicious_messages = []
    for channel in ctx.guild.text_channels:
        try:
            async for message in channel.history(limit=limit):
                if contains_suspicious_link(message.content):
                    suspicious_messages.append((channel.name, message.author.name, message.content, message.jump_url))
        except Exception as e:
            logger.error(f"Failed to scan channel {channel.name}: {e}")
    if suspicious_messages:
        report = "Suspicious messages found:\n"
        for channel_name, author_name, content, jump_url in suspicious_messages:
            report += f"- Channel: #{channel_name}, Author: {author_name}, [Jump to message]({jump_url})\n  Content: {content}\n"
        if len(report) > 2000:
            report = report[:1997] + "..."
        await ctx.send(report)
    else:
        await ctx.send("No suspicious links found in recent messages.")

@bot.command(name='setlogchannel')
@commands.has_permissions(administrator=True)
async def set_log_channel(ctx, channel: discord.TextChannel = None):
    """Set the log channel for this server."""
    if channel is None:
        await ctx.send("Please specify a channel. Usage: !setlogchannel #channel")
        return
    log_channels[ctx.guild.id] = channel.id
    await ctx.send(f"Log channel has been set to {channel.mention}")

@bot.event
async def on_ready():
    await bot.tree.sync()
    logger.info(f'Logged in as {bot.user} (ID: {bot.user.id})')
    logger.info('------')
    activity = discord.Game(name="WATCHING ORCA SERVERS")
    await bot.change_presence(status=discord.Status.online, activity=activity)
    
    for guild in bot.guilds:
        invites[guild.id] = await guild.invites()
        logger.debug(f'Cached invites for guild: {guild.name} ({guild.id})')




if __name__ == "__main__":
    bot.run(TOKEN)
