from telegram.ext import Updater, CommandHandler, CallbackContext, ConversationHandler, MessageHandler, Filters
from telegram import Update, ReplyKeyboardMarkup, InlineKeyboardMarkup, InlineKeyboardButton, ReplyKeyboardRemove
from Crypto.Cipher import AES
from base64 import b64decode

from utils import *
from wireguard import *
from bird import *

import re
import gnupg
import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

updater = Updater(token=BOT_TOKEN)
dispatcher = updater.dispatcher

if not os.path.exists(GNUPG_HOME):
    os.makedirs(GNUPG_HOME)
gpg = gnupg.GPG(gnupghome=GNUPG_HOME)

aes = AES.new(IPID_KEY.encode(), AES.MODE_ECB)

ipv4_pattern = re.compile(r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
dn42_ipv4_pattern = re.compile(r'^172\.2[0-3]\.((25[0-5]|2[0-4]\d|[01]?\d\d?)\.)(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
ipv6_pattern = re.compile(r'^([\da-fA-F]{1,4}:){6}((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$|^::([\da-fA-F]{1,4}:){0,4}((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$|^([\da-fA-F]{1,4}:):([\da-fA-F]{1,4}:){0,3}((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$|^([\da-fA-F]{1,4}:){2}:([\da-fA-F]{1,4}:){0,2}((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$|^([\da-fA-F]{1,4}:){3}:([\da-fA-F]{1,4}:){0,1}((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$|^([\da-fA-F]{1,4}:){4}:((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$|^([\da-fA-F]{1,4}:){7}[\da-fA-F]{1,4}$|^:((:[\da-fA-F]{1,4}){1,6}|:)$|^[\da-fA-F]{1,4}:((:[\da-fA-F]{1,4}){1,5}|:)$|^([\da-fA-F]{1,4}:){2}((:[\da-fA-F]{1,4}){1,4}|:)$|^([\da-fA-F]{1,4}:){3}((:[\da-fA-F]{1,4}){1,3}|:)$|^([\da-fA-F]{1,4}:){4}((:[\da-fA-F]{1,4}){1,2}|:)$|^([\da-fA-F]{1,4}:){5}:([\da-fA-F]{1,4})?$|^([\da-fA-F]{1,4}:){6}:$')
domain_pattern = re.compile(r'^(?=^.{3,255}$)[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$')
wireguard_key_pattern = re.compile(r'^[0-9A-Za-z+/=]{44}$')

wait_for_peer_markup = InlineKeyboardMarkup([
    [
        InlineKeyboardButton('来和我Peer！', url='https://t.me/{}'.format(updater.bot.username)),
        InlineKeyboardButton('Autopeer Bot', url='https://t.me/{}'.format(updater.bot.username)),
    ]
])


def start(update: Update, context: CallbackContext):
    update.message.reply_text(f'Hi! Welcome to peer with MolMoe Network {NODE_NAME} node! Reply with /peer to start '
                              f'peering process.', reply_markup=ReplyKeyboardRemove())


def ping(update: Update, context: CallbackContext):
    if len(context.args) == 0:
        update.message.reply_text('Usage: /ping [target]')
        return
    msg = update.message.reply_text('Pinging...')
    msg.edit_text('```\n' + subprocess.run(
            ['ping', context.args[0], '-c', '4', '-W', '5'],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT).stdout.decode() + '\n```', parse_mode='MarkdownV2', reply_markup=wait_for_peer_markup)


def ping4(update: Update, context: CallbackContext):
    if len(context.args) == 0:
        update.message.reply_text('Usage: /ping4 [target]')
        return
    msg = update.message.reply_text('Pinging...')
    msg.edit_text('```\n' + subprocess.run(
            ['ping', context.args[0], '-c', '4', '-W', '5', '-4'],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT).stdout.decode() + '\n```', parse_mode='MarkdownV2', reply_markup=wait_for_peer_markup)


def ping6(update: Update, context: CallbackContext):
    if len(context.args) == 0:
        update.message.reply_text('Usage: /ping6 [target]')
        return
    msg = update.message.reply_text('Pinging...')
    msg.edit_text('```\n' + subprocess.run(
            ['ping', context.args[0], '-c', '4', '-W', '5', '-6'],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT).stdout.decode() + '\n```', parse_mode='MarkdownV2', reply_markup=wait_for_peer_markup)


def traceroute(update: Update, context: CallbackContext):
    if len(context.args) == 0:
        update.message.reply_text('Usage: /traceroute [target]')
        return
    msg = update.message.reply_text('Tracing route in 10s...')
    msg.edit_text('```\n' + subprocess.run(
            ['timeout', '15s', 'traceroute', context.args[0]],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT).stdout.decode() + '\n```', parse_mode='MarkdownV2', reply_markup=wait_for_peer_markup)


def traceroute4(update: Update, context: CallbackContext):
    if len(context.args) == 0:
        update.message.reply_text('Usage: /traceroute4 [target]')
        return
    msg = update.message.reply_text('Tracing route in 10s...')
    msg.edit_text('```\n' + subprocess.run(
            ['timeout', '15s', 'traceroute', '-4', context.args[0]],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT).stdout.decode() + '\n```', parse_mode='MarkdownV2', reply_markup=wait_for_peer_markup)


def traceroute6(update: Update, context: CallbackContext):
    if len(context.args) == 0:
        update.message.reply_text('Usage: /traceroute6 [target]')
        return
    msg = update.message.reply_text('Tracing route in 10s...')
    msg.edit_text('```\n' + subprocess.run(
            ['timeout', '15s', 'traceroute', '-6', context.args[0]],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT).stdout.decode() + '\n```', parse_mode='MarkdownV2', reply_markup=wait_for_peer_markup)


# States of peering conversation
GPG_PUBKEY, GPG_SIGN, SSH_SIGN, ENDPOINT, PORT, IPV4, LINK_LOCAL, PUBLICKEY, MP, END = range(10)


def cancel(update: Update, context: CallbackContext):
    update.message.reply_text('Peering request is canceled.')
    return ConversationHandler.END


def peer(update: Update, context: CallbackContext):
    if update.effective_chat.type != 'private':
        update.message.reply_text('This command can be used only in private chat.')
        return ConversationHandler.END
    update.message.reply_text(f'Welcome to peering with me\! Send me with /cancel to cancel your request\. Please send me '
                              f'your DN42 ASN\. The ASN is like `AS424242XXXX` and should be registered on '
                              f'https://git\.dn42\.dev/ first\.', parse_mode='MarkdownV2')
    return GPG_PUBKEY


def gpg_pubkey(update: Update, context: CallbackContext):
    if re.match(r'^AS\d+$', update.message.text) is None:
        update.message.reply_text('Invalid ASN. Peering process is canceled.')
        return ConversationHandler.END
    if len(update.message.text) != 12:
        update.message.reply_text('Thank you for peering with me. You have a special ASN, so please contact '
                                  '@TheresaJune for peering. Peering process is canceled.')
        return ConversationHandler.END
    try:
        context.user_data['asn'], context.user_data['mntner'] = get_maintainer(update.message.text)
        context.user_data['gpg_id'] = get_gpg_key(context.user_data['mntner'])
    except InvalidASNorIP:
        update.message.reply_text('ASN not found in DN42 registry. Please try again.')
        return GPG_PUBKEY
    except NoGPGFingerprint:
        update.message.reply_text('Currently this bot only supports networks whose maintainer registered an OpenPGP '
                                  'fingerprint on DN42 registry. You may peer with me by contacting @TheresaJune. '
                                  'Peering process is canceled.')
        return ConversationHandler.END
    update.message.reply_text(f'Please send me your GPG public key `{context.user_data["gpg_id"]}` as an attachment:', parse_mode='MarkdownV2')
    return GPG_SIGN


def gpg_sign(update: Update, context: CallbackContext):
    document = update.message.document
    if document.file_size > 100 * 1024:
        update.message.reply_text('File is larger than 100KB. Please try again.')
        return GPG_SIGN
    gpg_import = gpg.import_keys(context.bot.get_file(document.file_id).download_as_bytearray())
    if context.user_data["gpg_id"] not in gpg_import.fingerprints:
        update.message.reply_text('Invalid GPG public key or the key does not match your fingerprint. Please try again.')
        return GPG_SIGN
    context.user_data['arg'] = get_arg(context.user_data['asn'])
    update.message.reply_text(f'Please sign the string `{context.user_data["arg"]}` with GPG key `{context.user_data["gpg_id"]}` and reply your '
                              f'cleartext signature\.', parse_mode='MarkdownV2')
    return ENDPOINT


def endpoint(update: Update, context: CallbackContext):
    context.user_data['gpg_sign'] = update.message.text
    with open(f'/tmp/{context.user_data["gpg_id"]}_{context.user_data["arg"]}.asc', 'w') as f:
        f.write(update.message.text)
    gpg_verify = gpg.verify_data(f'/tmp/{context.user_data["gpg_id"]}_{context.user_data["arg"]}.asc', context.user_data['arg'].encode())
    os.remove(f'/tmp/{context.user_data["gpg_id"]}_{context.user_data["arg"]}.asc')
    if not gpg_verify.valid or gpg_verify.pubkey_fingerprint != context.user_data['gpg_id']:
        update.message.reply_text('Invalid signature. Please try again.')
        return ENDPOINT
    if CERNET:
        update.message.reply_text('Please visit https://ipid.mol.moe/ with your CERNET IPv6 address. Make sure the IP '
                                  'shown on this site is your CERNET IPv6 endpoint and send the IPID to me.')
        return PORT
    else:
        update.message.reply_text(f'Please send me your endpoint\. The endpoint should be like `endpoint.example.com` '
                                  f'or `12.34.56.78` or `2001:123::1`\.', parse_mode='MarkdownV2')
        return PORT


def port(update: Update, context: CallbackContext):
    if CERNET:
        try:
            ip, timestamp = aes.decrypt(b64decode(update.message.text)).decode().split('|')
            timestamp = int(timestamp[:10])
            logging.debug(ip)
            logging.debug(timestamp)
            if time.time() - timestamp > 300:
                update.message.reply_text('Your IPID is expired. Please try again.')
                return PORT
            if not ip.startswith('2001:da8:') and not ip.startswith('2001:250:'):
                update.message.reply_text('Invalid CERNET IPv6. Please try again.')
                return PORT
            context.user_data['endpoint'] = '[' + ip + ']'
        except Exception:
            update.message.reply_text('Invalid IPID. Please try again.')
            return PORT
    else:
        endpoint_type = None
        if re.match(ipv4_pattern, update.message.text) is not None:
            endpoint_type = 'ipv4'
            context.user_data['endpoint'] = update.message.text
        elif re.match(ipv6_pattern, update.message.text) is not None:
            endpoint_type = 'ipv6'
            context.user_data['endpoint'] = '[' + update.message.text + ']'
        elif re.match(domain_pattern, update.message.text) is not None:
            endpoint_type = 'domain'
            context.user_data['endpoint'] = update.message.text
        if endpoint_type is None:
            update.message.reply_text('Invalid endpoint. Please try again.')
            return ENDPOINT
    update.message.reply_text(f'Please send me your listening port of the tunnel.')
    return IPV4


def ipv4(update: Update, context: CallbackContext):
    context.user_data['port'] = update.message.text
    try:
        if int(update.message.text) < 0 or int(update.message.text) > 65536:
            raise ValueError
    except ValueError:
        update.message.reply_text('Invalid port. Please try again.')
        return IPV4
    update.message.reply_text(f'Please send me your DN42 IPv4 address.')
    return LINK_LOCAL


def link_local(update: Update, context: CallbackContext):
    context.user_data['ipv4'] = update.message.text
    if re.match(dn42_ipv4_pattern, update.message.text) is None:
        update.message.reply_text('Invalid DN42 IPv4.Please try again.')
        return LINK_LOCAL
    asn, _ = get_maintainer(update.message.text)
    if context.user_data['asn'] != asn:
        update.message.reply_text('ASN of DN42 IPv4 does not match. Please try again.')
        return LINK_LOCAL
    update.message.reply_text(f'Please send me your IPv6 link-local address of the tunnel.')
    return PUBLICKEY


def publickey(update: Update, context: CallbackContext):
    context.user_data['link_local'] = update.message.text
    if re.match(ipv6_pattern, update.message.text) is None or not update.message.text.startswith('fe80'):
        update.message.reply_text('Invalid link-local IPv6 address. Please try again.')
        return PUBLICKEY
    update.message.reply_text(f'Please send me your WireGuard public key:')
    return MP


def mp(update: Update, context: CallbackContext):
    context.user_data['publickey'] = update.message.text
    if re.match(wireguard_key_pattern, update.message.text) is None:
        update.message.reply_text('Invalid WireGuard public key. Please try again.')
        return MP
    markup = ReplyKeyboardMarkup(keyboard=[['Yes', 'No']], one_time_keyboard=True)
    update.message.reply_text('Do you want to enable multi-protocol?', reply_markup=markup)
    return END


def end(update: Update, context: CallbackContext):
    name = 'd_' + str(ip2int(context.user_data['ipv4']))
    add_wg_peer(
        name,
        context.user_data['asn'][-5:],
        context.user_data['ipv4'],
        context.user_data['publickey'],
        context.user_data['endpoint'] + ':' + context.user_data['port']
    )
    if update.message.text == 'Yes':
        add_bird_peer_mp(
            name,
            context.user_data['asn'][2:],
            context.user_data['link_local'],
        )
    elif update.message.text == 'No':
        add_bird_peer_nmp(
            name,
            context.user_data['asn'][2:],
            context.user_data['ipv4'],
            context.user_data['link_local'],
        )
    else:
        update.message.reply_text('Invalid input.')
        return END
    update.message.reply_text(f'We have configured your peer\. \nYou should write `{LOCAL_ENDPOINT}:{context.user_data["asn"][-5:]}` as endpoint in your WireGuard configuration\. You can now check the peering status\.', parse_mode='MarkdownV2')
    return ConversationHandler.END


def delete(update: Update, context: CallbackContext):
    update.message.reply_text('This command is not implemented yet and is still under development.')


def error(update: Update, context: CallbackContext):
    logger.warning('Update "%s" caused error "%s"', update, context.error)
    update.message.reply_text('Ouch, something went wrong. Please report this issue to @TheresaJune.')


if __name__ == '__main__':
    dispatcher.add_handler(CommandHandler('start', start, run_async=True))
    dispatcher.add_handler(CommandHandler('ping', ping, run_async=True))
    dispatcher.add_handler(CommandHandler('ping4', ping4, run_async=True))
    dispatcher.add_handler(CommandHandler('ping6', ping6, run_async=True))
    dispatcher.add_handler(ConversationHandler(
        entry_points=[CommandHandler('peer', peer)],
        states={
            GPG_PUBKEY: [MessageHandler(Filters.text & ~Filters.command, gpg_pubkey, run_async=True)],
            GPG_SIGN: [MessageHandler(Filters.document & ~Filters.command, gpg_sign, run_async=True)],
            ENDPOINT: [MessageHandler(Filters.text & ~Filters.command, endpoint, run_async=True)],
            PORT: [MessageHandler(Filters.text & ~Filters.command, port, run_async=True)],
            IPV4: [MessageHandler(Filters.text & ~Filters.command, ipv4, run_async=True)],
            LINK_LOCAL: [MessageHandler(Filters.text & ~Filters.command, link_local, run_async=True)],
            PUBLICKEY: [MessageHandler(Filters.text & ~Filters.command, publickey, run_async=True)],
            MP: [MessageHandler(Filters.text & ~Filters.command, mp, run_async=True)],
            END: [MessageHandler(Filters.regex('^(Yes|No)$') & ~Filters.command, end, run_async=True)]
        },
        fallbacks=[CommandHandler('cancel', cancel, run_async=True)],
        conversation_timeout=600,
        run_async=True
    ))
    dispatcher.add_handler(CommandHandler('traceroute', traceroute, run_async=True))
    dispatcher.add_handler(CommandHandler('trace', traceroute, run_async=True))
    dispatcher.add_handler(CommandHandler('traceroute4', traceroute4, run_async=True))
    dispatcher.add_handler(CommandHandler('traceroute6', traceroute6, run_async=True))
    dispatcher.add_handler(CommandHandler('delete', delete, run_async=True))
    dispatcher.add_error_handler(error)

    updater.start_polling()

    updater.idle()
