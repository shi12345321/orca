import os
import re
import asyncio
import logging
import aiohttp
import discord
from discord.ext import commands
from discord import app_commands
from dotenv import load_dotenv
import socket
import subprocess
import datetime

load_dotenv()
TOKEN = os.getenv("DISCORD_TOKEN")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s:%(message)s")
logger = logging.getLogger("orca-bot")

intents = discord.Intents.default()
intents.members = True
intents.guilds = True
intents.message_content = True

bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)
start_time = datetime.datetime.utcnow()
log_channels = {}
invites = {}
whitelisted_users = {}  
suspicious_patterns = [
    r"https?://[^\s]*image-logger[^\s]*",
    r"https?://[^\s]*keylogger[^\s]*",
    r"https?://[^\s]*grabber[^\s]*",
    r"https?://[^\s]*stealer[^\s]*",
    r"https?://[^\s]*logger[^\s]*",
]

def contains_suspicious_link(text):
    if not text:
        return False
    for pattern in suspicious_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False

async def query_virustotal(url):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    async with aiohttp.ClientSession() as session:
        try:
            submit_url = "https://www.virustotal.com/api/v3/urls"
            async with session.post(submit_url, headers=headers, data={"url": url}) as resp:
                if resp.status not in [200, 201]:
                    logger.error("Failed to submit URL to VirusTotal.")
                    return None
                data = await resp.json()
                analysis_id = data["data"]["id"]

            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

            for _ in range(12):
                async with session.get(analysis_url, headers=headers) as report:
                    rdata = await report.json()
                    status = rdata["data"]["attributes"]["status"]

                    if status == "completed":
                        stats = rdata["data"]["attributes"]["stats"]
                        results = rdata["data"]["attributes"].get("results", {})
                        return {"stats": stats, "results": results, "analysis_id": analysis_id}

                await asyncio.sleep(5)

            logger.warning("VirusTotal scan timed out.")
            return None

        except Exception as e:
            logger.error(f"VirusTotal error: {e}")
            return None

async def send_log_message(guild_id, member, action):
    channel_id = log_channels.get(guild_id)
    if not channel_id:
        return

    channel = bot.get_channel(channel_id)
    if not channel:
        return

    embed = discord.Embed(color=discord.Color.dark_red())
    embed.set_author(name="ORCA SECURITY")
    embed.set_footer(text="Made by Alfie")
    embed.timestamp = discord.utils.utcnow()

    avatar = member.avatar.url if member.avatar else member.default_avatar.url
    embed.set_thumbnail(url=avatar)

    embed.add_field(name="Member", value=member.name, inline=True)
    embed.add_field(name="ID", value=str(member.id), inline=True)
    embed.add_field(name="Action", value=action, inline=False)

    await channel.send(embed=embed)

@bot.event
async def on_ready():
    activity = discord.Game(name="WATCHING ORCA SERVERS")
    await bot.change_presence(status=discord.Status.online, activity=activity)

    try:
        synced = await bot.tree.sync()
        logger.info(f"Synced {len(synced)} slash commands.")
    except Exception as e:
        logger.error(f"Slash command sync error: {e}")

    for guild in bot.guilds:
        try:
            invites[guild.id] = await guild.invites()
        except:
            pass

    logger.info(f"{bot.user} is now online.")

@bot.event
async def on_guild_join(guild):
    try:
        invites[guild.id] = await guild.invites()
    except:
        pass

@bot.event
async def on_member_join(member):
    if member.bot:
        try:
            async for entry in member.guild.audit_logs(limit=5, action=discord.AuditLogAction.bot_add):
                if entry.target.id == member.id:
                    inviter = entry.user
                    guild_id = member.guild.id
                    if inviter.id not in whitelisted_users.get(guild_id, set()):
                        try:
                            await member.guild.ban(member, reason="Unauthorized bot add")
                            await member.guild.ban(inviter, reason="Added unauthorized bot")
                        except:
                            pass
                    break
        except Exception as e:
            logger.error(f"Audit log error: {e}")

    await send_log_message(member.guild.id, member, "Member Joined")

@bot.event
async def on_member_remove(member):
    await send_log_message(member.guild.id, member, "Member Left")

@bot.event
async def on_message(message):
    if message.author.bot:
        return

    if contains_suspicious_link(message.content):
        warn = discord.Embed(
            description=f"⚠️ Suspicious link detected from {message.author.mention}",
            color=discord.Color.red()
        )
        await message.channel.send(embed=warn)

    await bot.process_commands(message)

@bot.command()
async def setlogchannel(ctx, channel: discord.TextChannel):
    if ctx.author.id != ctx.guild.owner_id:
        return await ctx.send("❌ Only the **server owner** can use this command.")

    log_channels[ctx.guild.id] = channel.id
    await ctx.send(f"Log channel set to {channel.mention}")

@bot.command()
async def scan(ctx, url: str):
    if not VIRUSTOTAL_API_KEY:
        return await ctx.send("VirusTotal API key missing.")

    await ctx.send(f"🔍 Scanning URL: {url}")
    result = await query_virustotal(url)

    if not result:
        return await ctx.send("❌ Failed to fetch VirusTotal results.")

    stats = result["stats"]

    embed = discord.Embed(
        title=f"Scan results for {url}",
        color=discord.Color.green() if stats["malicious"] == 0 else discord.Color.red()
    )

    embed.add_field(name="Malicious", value=stats["malicious"])
    embed.add_field(name="Suspicious", value=stats["suspicious"])
    embed.add_field(name="Harmless", value=stats["harmless"])
    embed.add_field(name="Undetected", value=stats["undetected"])

    await ctx.send(embed=embed)

@bot.command()
async def scanserver(ctx, limit: int = 100):
    if ctx.author.id != ctx.guild.owner_id:
        return await ctx.send("❌ Only the **server owner** can use this command.")

    await ctx.send(f"Scanning last {limit} messages across all channels...")

    found = []

    for channel in ctx.guild.text_channels:
        try:
            async for msg in channel.history(limit=limit):
                if contains_suspicious_link(msg.content):
                    found.append((channel.name, msg.author, msg.jump_url))
        except:
            pass

    if not found:
        return await ctx.send("✔ No suspicious links found.")

    report = "\n".join([f"#{c} - {a} → {link}" for c, a, link in found])[:1900]
    await ctx.send(f"⚠ Suspicious messages found:\n{report}")

@bot.command()
async def whitelist(ctx, user: discord.User):
    if ctx.author.id != ctx.guild.owner_id:
        return await ctx.send("HINDI KA OWNER TANGA")

    guild_id = ctx.guild.id
    if guild_id not in whitelisted_users:
        whitelisted_users[guild_id] = set()

    whitelisted_users[guild_id].add(user.id)
    await ctx.send(f"✔ {user.mention} has been whitelisted by the **server owner**.")

@bot.tree.command(name="whitelist", description="Whitelist a user so they can add bots.")
async def whitelist_slash(interaction: discord.Interaction, user: discord.User):

    if interaction.user.id != interaction.guild.owner_id:
        return await interaction.response.send_message(
            "HINDI KA OWNER TANGA",
            ephemeral=True
        )

    guild_id = interaction.guild_id

    if guild_id not in whitelisted_users:
        whitelisted_users[guild_id] = set()

    whitelisted_users[guild_id].add(user.id)

    await interaction.response.send_message(
        f"✔ {user.mention} has been whitelisted by the **server owner**.",
        ephemeral=True
    )

@bot.command()
async def avatar(ctx, user: discord.User = None):
    if user is None:
        user = ctx.author

    embed = discord.Embed(title=f"{user.name}'s Avatar", color=discord.Color.blue())
    embed.set_image(url=user.avatar.url if user.avatar else user.default_avatar.url)

    embed.add_field(name="PNG", value=f"[Link]({user.avatar.url.replace('webp', 'png') if user.avatar else user.default_avatar.url})", inline=True)
    embed.add_field(name="JPEG", value=f"[Link]({user.avatar.url.replace('webp', 'jpg') if user.avatar else user.default_avatar.url})", inline=True)
    embed.add_field(name="WebP", value=f"[Link]({user.avatar.url if user.avatar else user.default_avatar.url})", inline=True)
    embed.add_field(name="GIF", value=f"[Link]({user.avatar.url.replace('webp', 'gif') if user.avatar else user.default_avatar.url})", inline=True)

    await ctx.send(embed=embed)

@bot.command()
async def credits(ctx):
    embed = discord.Embed(title="Bot Credits", color=discord.Color.green())
    embed.set_author(name="ORCA SECURITY")
    embed.set_footer(text="Made by Alfie")
    embed.add_field(name="Creator", value="Alfie", inline=True)
    embed.add_field(name="Description", value="A security-focused Discord bot for monitoring and protecting servers.", inline=False)
    embed.add_field(name="Version", value="1.0.0", inline=True)
    embed.add_field(name="Library", value="discord.py", inline=True)
    await ctx.send(embed=embed)

@bot.command()
async def dnsdumpster(ctx, domain: str):
    url = f"https://dnsdumpster.com/"
    headers = {"User-Agent": "Mozilla/5.0"}

    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, headers=headers) as resp:
                if resp.status != 200:
                    return await ctx.send("❌ Failed to fetch DNSDumpster data.")

                html = await resp.text()
                embed = discord.Embed(title=f"DNSDumpster for {domain}", color=discord.Color.blue())
                embed.add_field(name="Note", value="Passive DNS data parsing not fully implemented. Use external tools for accurate data.", inline=False)
                await ctx.send(embed=embed)
        except Exception as e:
            await ctx.send(f"❌ Error: {e}")

@bot.command()
async def dnslookup(ctx, domain: str):
    try:
        records = socket.getaddrinfo(domain, None)
        embed = discord.Embed(title=f"DNS Records for {domain}", color=discord.Color.blue())
        for record in records[:10]:  # Limit to 10 records
            embed.add_field(name="Record", value=f"{record[4][0]}", inline=False)
        await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(f"❌ Error: {e}")

@bot.command()
async def orca(ctx):
    commands_list = [cmd.name for cmd in bot.commands]
    embed = discord.Embed(title="Available Commands", color=discord.Color.blue())
    embed.add_field(name="Commands", value="\n".join(commands_list), inline=False)
    await ctx.send(embed=embed)

@bot.command()
async def ping(ctx):
    latency = round(bot.latency * 1000)
    embed = discord.Embed(title="Bot Latency", color=discord.Color.green())
    embed.add_field(name="Ping", value=f"{latency}ms", inline=True)
    await ctx.send(embed=embed)

@bot.command()
async def pinghost(ctx, host: str):
    try:
        result = subprocess.run(["ping", "-c", "4", host], capture_output=True, text=True, timeout=10)
        embed = discord.Embed(title=f"Ping {host}", color=discord.Color.blue())
        embed.add_field(name="Output", value=f"```\n{result.stdout[:1000]}\n```", inline=False)
        await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(f"❌ Error: {e}")

@bot.command()
async def servericon(ctx):
    if ctx.guild.icon:
        embed = discord.Embed(title=f"{ctx.guild.name}'s Icon", color=discord.Color.blue())
        embed.set_image(url=ctx.guild.icon.url)
        await ctx.send(embed=embed)
    else:
        await ctx.send("❌ This server has no icon.")

@bot.command()
async def serverinfo(ctx):
    embed = discord.Embed(title=f"{ctx.guild.name} Info", color=discord.Color.blue())
    embed.add_field(name="Owner", value=ctx.guild.owner.mention, inline=True)
    embed.add_field(name="Members", value=ctx.guild.member_count, inline=True)
    embed.add_field(name="Channels", value=len(ctx.guild.channels), inline=True)
    embed.add_field(name="Roles", value=len(ctx.guild.roles), inline=True)
    embed.add_field(name="Created", value=ctx.guild.created_at.strftime("%Y-%m-%d"), inline=True)
    embed.set_thumbnail(url=ctx.guild.icon.url if ctx.guild.icon else None)
    await ctx.send(embed=embed)

@bot.command()
async def uptime(ctx):
    now = datetime.datetime.utcnow()
    uptime = now - start_time
    days, remainder = divmod(int(uptime.total_seconds()), 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    embed = discord.Embed(title="Bot Uptime", color=discord.Color.green())
    embed.add_field(name="Uptime", value=f"{days}d {hours}h {minutes}m {seconds}s", inline=True)
    await ctx.send(embed=embed)

@bot.command()
async def clonewebsite(ctx, url: str):
    if not url.startswith("http"):
        url = "http://" + url

    headers = {"User-Agent": "Mozilla/5.0"}

    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, headers=headers, timeout=10) as resp:
                if resp.status != 200:
                    return await ctx.send(f"❌ Failed to fetch website. Status: {resp.status}")

                html = await resp.text()
                preview = html[:1000] + ("..." if len(html) > 1000 else "")
                embed = discord.Embed(title=f"Cloned Website: {url}", color=discord.Color.blue())
                embed.add_field(name="HTML Preview", value=f"```\n{preview}\n```", inline=False)
                await ctx.send(embed=embed)
        except Exception as e:
            await ctx.send(f"❌ Error: {e}")

bot.run(TOKEN)
