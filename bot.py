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


from discord.ui import Select, View

class ChoiceSelect(Select):
    def __init__(self):
        self.message_map = {
            "rtb": "TO ALL ACTIVE pﾒs MEMBERS, KINDLY CONNECT TO OUR RADIO FREQUENCY AND RTB.",
            "meetup": "PSYCHEDELIC$ PATRON IS REQUESTING FOR MEET UP AT POSTAL [] WITH [GANG NAME] PATRON FOR KILLING OUR BELOVED [GANG NAME MEMBER].",
            "ISSUES/DANYOS": "PSYCHEDELIC$ IS REQUESTING A MEETUP WITH [GANG NAME] TO TALK ABOUT SOME FAMILY MATTERS. WE WILL BE WAITING HERE AT [LOCATION]",
            "turf_war_PSYCHEDELIC$": "/gc THE PSYCHEDELIC$  WILL BE INTERCEPTING AT THE LATEST TURF. SEE YA, GANG!",
            "turf_war_jaysu": "/gc WE ARE CHALLENGING ALL GANGS AND THE POLICE DEPARTMENT TO TEST YOUR WITS AGAINST PSYCHEDELIC$  @ 𝐀𝐋𝐀 𝐀𝐋𝐀 𝐍𝐈 𝐉𝐀𝐘𝐒𝐔 [𝐏𝐎𝐒𝐓𝐀𝐋 𝟗𝟑𝟗𝟑] - TURFWAR!",
            "turf_war_kortz": "/gc WE ARE CHALLENGING ALL GANGS AND THE POLICE DEPARTMENT TO TEST YOUR WITS AGAINST PSYCHEDELIC$  @ 𝐊𝐎𝐑𝐓𝐙 𝐂𝐄𝐍𝐓𝐄𝐑 [𝐏𝐎𝐒𝐓𝐀𝐋 𝟔𝟎𝟎𝟎] - TURFWAR!",
            "turf_war_redwood": "/gc WE ARE CHALLENGING ALL GANGS AND THE POLICE DEPARTMENT TO TEST YOUR WITS AGAINST PSYCHEDELIC$  @ 𝐑𝐄𝐃𝐖𝐎𝐎𝐃 𝐋𝐈𝐆𝐇𝐓𝐒 𝐓𝐑𝐀𝐂𝐊 [𝐏𝐎𝐒𝐓𝐀𝐋 𝟒𝟎𝟎𝟕] - TURFWAR!",
            "turf_war_sisyphus": "/gc WE ARE CHALLENGING ALL GANGS AND THE POLICE DEPARTMENT TO TEST YOUR WITS AGAINST PSYCHEDELIC$  @ 𝐒𝐈𝐒𝐘𝐏𝐇𝐔𝐒 𝐓𝐇𝐄𝐀𝐓𝐄𝐑 [𝐏𝐎𝐒𝐓𝐀𝐋 𝟓𝟎𝟐𝟔] - TURFWAR!",
            "gwar_declaration": "ONGOING FAMILY WAR AGAINST [GANG NAME], 1ST WAVE. ANYONE WHOSE WEARING THEIR GANG UNIFORM WILL BE KILLED ON SIGHT. CITIZEN PLEASE BE ADVISED."
        }
        options = [
            discord.SelectOption(label="RTB", description=" RTB ", value="rtb"),
            discord.SelectOption(label="MEET UP REQUEST", description="MEET UP", value="meetup"),
            discord.SelectOption(label="Issues Danyos", description="DANYOS", value="ISSUES/DANYOS"),
            discord.SelectOption(label="Turf War PSYCHEDELIC$", description="Intercepting Turf War", value="turf_war_PSYCHEDELIC$"),
            discord.SelectOption(label="Turf War Ala Ala Ni Jaysu", description="Postal 9393 Turf War", value="turf_war_jaysu"),
            discord.SelectOption(label="Turf War Kortz Center", description="Postal 6000 Turf War", value="turf_war_kortz"),
            discord.SelectOption(label="Turf War Redwood Lights Track", description="Postal 4007 Turf War", value="turf_war_redwood"),
            discord.SelectOption(label="Turf War Sisyphus Theater", description="Postal 5026 Turf War", value="turf_war_sisyphus"),
            discord.SelectOption(label="GANG WAR DECLARATION", description="GWAR", value="gwar_declaration"),
        ]
        super().__init__(placeholder="Choose a message...", min_values=1, max_values=1, options=options)

    async def callback(self, interaction: discord.Interaction):
        selected_key = self.values[0]
        full_message = self.message_map.get(selected_key, "Unknown selection")
        await interaction.response.send_message(full_message, ephemeral=True)

@bot.command(name='template')
async def template(ctx):
    """Send a message with choices as a dropdown select menu."""
    select = ChoiceSelect()
    view = View()
    view.add_item(select)
    await ctx.send("Please choose a message:", view=view)

class LexusGpackSelect(Select):
    def __init__(self):
        self.message_map = {
            "v7": "LEXUS V7 https://cdn.discordapp.com/attachments/1360935586835333130/1361759707701969188/Lexus_Bundle_V17.rar?ex=6864c7ce&is=6863764e&hm=9d14bdb7c68307fd192dd5c097f532dd6f76a93951774eeb3529b20e967dc9e7&",
            "exclusive_v3": "EXCLUSIVE LEXUS V3 https://cdn.discordapp.com/attachments/1310176656169898015/1341159143012302960/Lexus_Bundle_V10.rar?ex=6864fb89&is=6863aa09&hm=e520e52f2d26b847f2397e6d7749b4b56b204c1c65754da6b6aa16eb90fa8d96&",
            "v8": "LEXUS V8 https://cdn.discordapp.com/attachments/1310176656169898015/1341159143012302960/Lexus_Bundle_V10.rar?ex=6864fb89&is=6863aa09&hm=e520e52f2d26b847f2397e6d7749b4b56b204c1c65754da6b6aa16eb90fa8d96&",
            "v10": "LEXUS V10 https://cdn.discordapp.com/attachments/1333750798521208864/1333750800614428735/YVL_V3.rar?ex=686465fa&is=6863147a&hm=c98ee2e27761a7dd3f3d2d3c2b748349054a786c3aa5e40a7a7dd54a2d4c627d&",
            "v11": "LEXUS V11 https://cdn.discordapp.com/attachments/1333750798521208864/1333750800614428735/YVL_V3.rar?ex=686465fa&is=6863147a&hm=c98ee2e27761a7dd3f3d2d3c2b748349054a786c3aa5e40a7a7dd54a2d4c627d&",
            "v12": "LEXUS V12 https://www.mediafire.com/file/s42046j9nhdp56l/Lexus_Bundle_V12a.rar/file",
            "v14": "LEXUS V14 https://www.mediafire.com/file/s42046j9nhdp56l/Lexus_Bundle_V12a.rar/file",
            "v17": "LEXUS V17 https://cdn.discordapp.com/attachments/1360935586835333130/1361759707701969188/Lexus_Bundle_V17.rar?ex=6864c7ce&is=6863764e&hm=9d14bdb7c68307fd192dd5c097f532dd6f76a93951774eeb3529b20e967dc9e7&",
            "v21": "LEXUS V21",
            "v23": "LEXUS V23 https://cdn.discordapp.com/attachments/1365725355410981005/1368950059974131803/Lexus_Bundle_V23.rar?ex=68649258&is=686340d8&hm=421c37104c300995b1a90ad70aeee6185e5cc40f556a04b2413255b968a1d730&",
            "v25": "LEXUS V25 https://cdn.discordapp.com/attachments/1365725355410981005/1368950059974131803/Lexus_Bundle_V23.rar?ex=68649258&is=686340d8&hm=421c37104c300995b1a90ad70aeee6185e5cc40f556a04b2413255b968a1d730&",
            "v27": "LEXUS V27 https://cdn.discordapp.com/attachments/1365725355410981005/1368950059974131803/Lexus_Bundle_V23.rar?ex=68649258&is=686340d8&hm=421c37104c300995b1a90ad70aeee6185e5cc40f556a04b2413255b968a1d730&",
            "v28": "LEXUS V28 https://cdn.discordapp.com/attachments/1365725355410981005/1368950059974131803/Lexus_Bundle_V23.rar?ex=68649258&is=686340d8&hm=421c37104c300995b1a90ad70aeee6185e5cc40f556a04b2413255b968a1d730&",
            "v29": "LEXUS V29 https://cdn.discordapp.com/attachments/1365725355410981005/1368950059974131803/Lexus_Bundle_V23.rar?ex=68649258&is=686340d8&hm=421c37104c300995b1a90ad70aeee6185e5cc40f556a04b2413255b968a1d730&"
        }
        options = [
            discord.SelectOption(label="LEXUS V7", description="Lexus version 7", value="v7"),
            discord.SelectOption(label="EXCLUSIVE LEXUS V3", description="Exclusive Lexus version 3", value="exclusive_v3"),
            discord.SelectOption(label="LEXUS V8", description="Lexus version 8", value="v8"),
            discord.SelectOption(label="LEXUS V10", description="Lexus version 10", value="v10"),
            discord.SelectOption(label="LEXUS V11", description="Lexus version 11", value="v11"),
            discord.SelectOption(label="LEXUS V12", description="Lexus version 12", value="v12"),
            discord.SelectOption(label="LEXUS V14", description="Lexus version 14", value="v14"),
            discord.SelectOption(label="LEXUS V17", description="Lexus version 17", value="v17"),
            discord.SelectOption(label="LEXUS V21", description="Lexus version 21", value="v21"),
            discord.SelectOption(label="LEXUS V23", description="Lexus version 23", value="v23"),
            discord.SelectOption(label="LEXUS V25", description="Lexus version 25", value="v25"),
            discord.SelectOption(label="LEXUS V27", description="Lexus version 27", value="v27"),
            discord.SelectOption(label="LEXUS V28", description="Lexus version 28", value="v28"),
            discord.SelectOption(label="LEXUS V29", description="Lexus version 29", value="v29"),
        ]
        super().__init__(placeholder="Choose a Lexus Gpack option...", min_values=1, max_values=1, options=options)

    async def callback(self, interaction: discord.Interaction):
        selected_key = self.values[0]
        full_message = self.message_map.get(selected_key, "Unknown Lexus Gpack selection")
        await interaction.response.send_message(full_message, ephemeral=True)

class YvlGpackSelect(Select):
    def __init__(self):
        self.message_map = {
            "yvl4": " https://cdn.discordapp.com/attachments/1278607130823360552/1331217515501584384/YVL_V4.rar?ex=6864692c&is=686317ac&hm=871576910d5d3885a572049e1afeb1ec8306e8a0b14fcfc4e618a6b851f63137&",
            "yvl5": " https://cdn.discordapp.com/attachments/1278607130823360552/1331217515501584384/YVL_V4.rar?ex=6864692c&is=686317ac&hm=871576910d5d3885a572049e1afeb1ec8306e8a0b14fcfc4e618a6b851f63137&",
            "yvl2": " https://cdn.discordapp.com/attachments/1333750798521208864/1333750800614428735/YVL_V3.rar?ex=686465fa&is=6863147a&hm=c98ee2e27761a7dd3f3d2d3c2b748349054a786c3aa5e40a7a7dd54a2d4c627d&",
            "yvl3": " https://cdn.discordapp.com/attachments/1333750798521208864/1333750800614428735/YVL_V3.rar?ex=686465fa&is=6863147a&hm=c98ee2e27761a7dd3f3d2d3c2b748349054a786c3aa5e40a7a7dd54a2d4c627d&"
        }
        options = [
            discord.SelectOption(label="YVL 4", description="YVL version 4", value="yvl4"),
            discord.SelectOption(label="YVL 5", description="YVL version 5", value="yvl5"),
            discord.SelectOption(label="YVL 2", description="YVL version 2", value="yvl2"),
            discord.SelectOption(label="YVL 3", description="YVL version 3", value="yvl3"),
        ]
        super().__init__(placeholder="Choose a YVL Gpack option...", min_values=1, max_values=1, options=options)

    async def callback(self, interaction: discord.Interaction):
        selected_key = self.values[0]
        full_message = self.message_map.get(selected_key, "Unknown YVL Gpack selection")
        await interaction.response.send_message(full_message, ephemeral=True)



class ShinGpackSelect(Select):
    def __init__(self):
        self.message_map = {
            "shinv4": "https://cdn.discordapp.com/attachments/1375230764454772736/1375251218284286032/shinv4.zip?ex=68651541&is=6863c3c1&hm=5d40f4f79402671aea34193f7431facbed16093148ecad31f1fcc512282e6cf6&",
            "shinv5": "https://cdn.discordapp.com/attachments/1375230764454772736/1379322328722440345/shinv8.zip?ex=6864bb85&is=68636a05&hm=84139bd5a64bf9c7f8fb58b48ee6d1111bfaaa2498a228856af2a23081b6e9a1&",
            "shinv8": "https://cdn.discordapp.com/attachments/1375230764454772736/1379322328722440345/shinv8.zip?ex=6864bb85&is=68636a05&hm=84139bd5a64bf9c7f8fb58b48ee6d1111bfaaa2498a228856af2a23081b6e9a1&",
            "shinv11": "https://cdn.discordapp.com/attachments/1371774190377766912/1384779212254216203/shinv11.zip?ex=6864cf24&is=68637da4&hm=babdec9fe0d4ac1d9f99fcdea014ca42ced5dd028807d7c4789f31c082a8cc74&"
        }
        options = [
            discord.SelectOption(label="Shin V4", description="Shin version 4", value="shinv4"),
            discord.SelectOption(label="Shin V5", description="Shin version 5", value="shinv5"),
            discord.SelectOption(label="Shin V8", description="Shin version 8", value="shinv8"),
            discord.SelectOption(label="Shin V11", description="Shin version 11", value="shinv11"),
        ]
        super().__init__(placeholder="Choose a Shin Gpack option...", min_values=1, max_values=1, options=options)

    async def callback(self, interaction: discord.Interaction):
        selected_key = self.values[0]
        full_message = self.message_map.get(selected_key, "Unknown Shin Gpack selection")
        await interaction.response.send_message(full_message, ephemeral=True)

class GpackSelect(Select):
    def __init__(self):
        self.message_map = {
            "lexus": "Lexus Gpack group selected.",
            "yvl": "YVL Gpack group selected.",
            "shin": "Shin Gpack group selected."
        }
        options = [
            discord.SelectOption(label="Lexus Gpack", description="Select Lexus Gpack options", value="lexus"),
            discord.SelectOption(label="YVL Gpack", description="Select YVL Gpack options", value="yvl"),
            discord.SelectOption(label="Shin Gpack", description="Select Shin Gpack options", value="shin"),
        ]
        super().__init__(placeholder="Choose a gpack group...", min_values=1, max_values=1, options=options)

    async def callback(self, interaction: discord.Interaction):
        selected_key = self.values[0]
        if selected_key == "lexus":
            select = LexusGpackSelect()
            view = View()
            view.add_item(select)
            await interaction.response.send_message("Please choose a Lexus Gpack option:", view=view, ephemeral=True)
        elif selected_key == "yvl":
            select = YvlGpackSelect()
            view = View()
            view.add_item(select)
            await interaction.response.send_message("Please choose a YVL Gpack option:", view=view, ephemeral=True)
       
        elif selected_key == "shin":
            select = ShinGpackSelect()
            view = View()
            view.add_item(select)
            await interaction.response.send_message("Please choose a Shin Gpack option:", view=view, ephemeral=True)
        else:
            await interaction.response.send_message("Unknown selection", ephemeral=True)

@bot.command(name='gpack')
async def gpack(ctx):
    """Send a message with choices as a dropdown select menu for gpack."""
    select = GpackSelect()
    view = View()
    view.add_item(select)
    await ctx.send("Please choose a gpack group:", view=view)

@bot.tree.command(name='gpack')
async def gpack_slash(interaction: discord.Interaction):
    """Send a message with choices as a dropdown select menu for gpack."""
    select = GpackSelect()
    view = View()
    view.add_item(select)
    await interaction.response.send_message("Please choose a gpack group:", view=view)

class SpackSelect(Select):
    def __init__(self):
        self.message_map = {
            "sp_ni_hukom": "SP NI HUKOM https://cdn.discordapp.com/attachments/1296977046185967627/1307648987611926558/SPNIHUKOM.rar?ex=68650585&is=6863b405&hm=fbc8feb5edae3b418e87b5fecd73892df8a624204a4faf70692a70ce2017a926&",
            "boogie_bank": "BOOGIE BANK https://cdn.discordapp.com/attachments/1296977046185967627/1307648987611926558/SPNIHUKOM.rar?ex=68650585&is=6863b405&hm=fbc8feb5edae3b418e87b5fecd73892df8a624204a4faf70692a70ce2017a926&",
            "santino": "SANTINO https://cdn.discordapp.com/attachments/1298540264796717137/1348058598634422322/Santino.rar?ex=686508a7&is=6863b727&hm=3b02021bb6eb1e8cdf2cedf2008ea809128e7a5b88079d8d45c3e740a005b9e7&"
        }
        options = [
            discord.SelectOption(label="SP NI HUKOM", description="SP NI HUKOM", value="sp_ni_hukom"),
            discord.SelectOption(label="BOOGIE BANK", description="BOOGIE BANK", value="boogie_bank"),
            discord.SelectOption(label="SANTINO", description="SANTINO", value="santino"),
        ]
        super().__init__(placeholder="Choose a spack option...", min_values=1, max_values=1, options=options)

    async def callback(self, interaction: discord.Interaction):
        selected_key = self.values[0]
        full_message = self.message_map.get(selected_key, "Unknown spack selection")
        await interaction.response.send_message(full_message, ephemeral=True)

@bot.command(name='spack')
async def spack(ctx):
    """Send a message with choices as a dropdown select menu for spack."""
    select = SpackSelect()
    view = View()
    view.add_item(select)
    await ctx.send("Please choose a spack option:", view=view)

@bot.tree.command(name='spack')
async def spack_slash(interaction: discord.Interaction):
    """Send a message with choices as a dropdown select menu for spack."""
    select = SpackSelect()
    view = View()
    view.add_item(select)
    await interaction.response.send_message("Please choose a spack option:", view=view)

class TreesSelect(Select):
    def __init__(self):
        self.message_map = {
            "orange_trees": "orange trees https://drive.google.com/file/d/1UND1eJPmSStJhcgqQLE0QW2ayrV1M3Om/view?usp=sharing",
            "red_trees": "red trees https://drive.google.com/file/d/1UND1eJPmSStJhcgqQLE0QW2ayrV1M3Om/view?usp=sharing",
            "pink_trees": "pink trees https://drive.google.com/file/d/1UND1eJPmSStJhcgqQLE0QW2ayrV1M3Om/view?usp=sharing"
        }
        options = [
            discord.SelectOption(label="Orange Trees", description="Orange trees", value="orange_trees"),
            discord.SelectOption(label="Red Trees", description="Red trees", value="red_trees"),
            discord.SelectOption(label="Pink Trees", description="Pink trees", value="pink_trees"),
        ]
        super().__init__(placeholder="Choose a trees option...", min_values=1, max_values=1, options=options)

    async def callback(self, interaction: discord.Interaction):
        selected_key = self.values[0]
        full_message = self.message_map.get(selected_key, "Unknown trees selection")
        await interaction.response.send_message(full_message, ephemeral=True)

@bot.command(name='trees')
async def trees(ctx):
    """Send a message with choices as a dropdown select menu for trees."""
    select = TreesSelect()
    view = View()
    view.add_item(select)
    await ctx.send("Please choose a trees option:", view=view)

@bot.tree.command(name='trees')
async def trees_slash(interaction: discord.Interaction):
    """Send a message with choices as a dropdown select menu for trees."""
    select = TreesSelect()
    view = View()
    view.add_item(select)
    await interaction.response.send_message("Please choose a trees option:", view=view)

class RoadsSelect(Select):
    def __init__(self):
        self.message_map = {
            "asphalt": "Asphalt https://drive.google.com/file/d/1EGda6IOw7z65sAZ6zG1PW2Lzypq-mWht/view?usp=drive_link",
            "german": "German https://drive.google.com/file/d/1uEIwDZ5Blo79ETId4sYyQL1ZsQ2Hu5iR/view",
            "wet_roads": "Wet roads https://drive.google.com/file/d/1ZXBr-ZY5Q1AkX-csZJWHZtaWbV9JdtdD/view",
            "miami": "Miami https://drive.google.com/file/d/1-G4S8bfLmP1AG-C3Ib9SQKtH4n1nDXQw/view"
        }
        options = [
            discord.SelectOption(label="Asphalt", description="Asphalt", value="asphalt"),
            discord.SelectOption(label="German", description="German", value="german"),
            discord.SelectOption(label="Wet Roads", description="Wet roads", value="wet_roads"),
            discord.SelectOption(label="Miami", description="Miami", value="miami"),
        ]
        super().__init__(placeholder="Choose a roads option...", min_values=1, max_values=1, options=options)

    async def callback(self, interaction: discord.Interaction):
        selected_key = self.values[0]
        full_message = self.message_map.get(selected_key, "Unknown roads selection")
        await interaction.response.send_message(full_message, ephemeral=True)

@bot.command(name='roads')
async def roads(ctx):
    """Send a message with choices as a dropdown select menu for roads."""
    select = RoadsSelect()
    view = View()
    view.add_item(select)
    await ctx.send("Please choose a roads option:", view=view)

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
