from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import AuthorizedSession
from google.oauth2.credentials import Credentials
import json
import os.path
import argparse
import logging
from tqdm import tqdm
import sys
from time import sleep
from collections import defaultdict

REPORT = defaultdict(int)


class TqdmHandler(logging.StreamHandler):
    def __init__(self):
        logging.StreamHandler.__init__(self)

    def emit(self, record):
        msg = self.format(record)
        tqdm.write(msg, file=sys.stderr)


def parse_args(arg_input=None):
    parser = argparse.ArgumentParser(description='Upload photos to Google Photos.')
    file_group = parser.add_argument_group()
    file_group.add_argument('root_dir', metavar='root_dir',
                            help='Root directory with subfolders to process.')
    file_group.add_argument('-t', '--extension', dest='extensions', required=False, action='append',
                            default=['jpg', 'mp4'],
                            help='Specify extension to proceed, other will skipped. Case-insensitive. Can be repeated.')
    file_group.add_argument('-e', '--exclude', dest='excludes', required=False, action='append',
                            default=['.thumbnails', '.picasaoriginals'],
                            help='Specify folders to exclude')

    parser.add_argument('--auth ', metavar='auth_file', dest='auth_file', default='client_id.json',
                        help='file for reading/storing user authentication tokens')

    parser.add_argument('-v', '--verbose', action='count', default=0, help='verbosity level, up to -vvv')
    parser.add_argument('-n', '--dry-run', dest='dry_run', required=False, action='store_true',
                        help='not make actual changes, just dry-run')

    # group_common.add_argument('--no-progress', action='store_true', dest='progressbar_disabled',
    #                           help='Progressbar disabled.')
    # group_common.add_argument('-fl', '--filename-log', dest='filename_log', metavar='stderr.log',
    #                           default=None, help='File with additional logging.')

    return parser.parse_args(arg_input)


def auth(scopes):
    flow = InstalledAppFlow.from_client_secrets_file('client_id.json', scopes=scopes)
    credentials = flow.run_local_server(host='localhost',
                                        port=8080,
                                        authorization_prompt_message="",
                                        success_message='The auth flow is complete; you may close this window.',
                                        open_browser=True)
    return credentials


def get_authorized_session(auth_token_file):
    scopes = ['https://www.googleapis.com/auth/photoslibrary',
              'https://www.googleapis.com/auth/photoslibrary.sharing']

    cred = None

    if auth_token_file:
        try:
            cred = Credentials.from_authorized_user_file(auth_token_file, scopes)
        except OSError as err:
            logging.debug("Error opening auth token file - {0}".format(err))
        except ValueError:
            logging.debug("Error loading auth tokens - Incorrect format")

    if not cred:
        cred = auth(scopes)

    session = AuthorizedSession(cred)

    if auth_token_file:
        try:
            save_cred(cred, auth_token_file)
        except OSError as err:
            logging.debug("Could not save auth tokens - {0}".format(err))

    return session


def save_cred(cred, auth_file):
    cred_dict = {
        'token': cred.token,
        'refresh_token': cred.refresh_token,
        'id_token': cred.id_token,
        'scopes': cred.scopes,
        'token_uri': cred.token_uri,
        'client_id': cred.client_id,
        'client_secret': cred.client_secret
    }

    with open(auth_file, 'w') as f:
        print(json.dumps(cred_dict), file=f)


# Generator to loop through all albums

def getAlbums(session, appCreatedOnly=False):
    params = {
        'excludeNonAppCreatedData': appCreatedOnly
    }

    while True:

        albums = session.get('https://photoslibrary.googleapis.com/v1/albums', params=params).json()

        logging.debug("Server response: {}".format(albums))

        if 'albums' in albums:

            for a in albums["albums"]:
                yield a

            if 'nextPageToken' in albums:
                params["pageToken"] = albums["nextPageToken"]
            else:
                return

        else:
            return


def create_or_retrieve_album(session, album_title):
    # Find albums created by this app to see if one matches album_title

    for a in getAlbums(session, True):
        if a["title"].lower() == album_title.lower():
            album_id = a["id"]
            logging.info("Uploading into EXISTING photo album -- \'{0}\'".format(album_title))
            return album_id

    # No matches, create new album

    create_album_body = json.dumps({"album": {"title": album_title}})
    # print(create_album_body)
    resp = session.post('https://photoslibrary.googleapis.com/v1/albums', create_album_body).json()

    logging.debug("Server response: {}".format(resp))

    if "id" in resp:
        logging.info("Uploading into NEW photo album -- \'{0}\'".format(album_title))
        return resp['id']
    else:
        logging.error("Could not find or create photo album '\{0}\'. Server Response: {1}".format(album_title, resp))
        return None


def upload_photos(session, path, photo_file_list, album_name, args):
    if not args.dry_run:
        album_id = create_or_retrieve_album(session, album_name) if album_name else None
        # interrupt upload if an upload was requested but could not be created
        if album_name and not album_id:
            return

    session.headers["Content-type"] = "application/octet-stream"
    session.headers["X-Goog-Upload-Protocol"] = "raw"
    for photo_file_name in tqdm(photo_file_list, desc='Files', leave=False):
        filename, extension = os.path.splitext(photo_file_name)
        if extension[1:].lower() in args.extensions:

            logging.info('Path: {}, file: {}'.format(path, photo_file_name))
            REPORT[album_name] += 1
        else:
            logging.info('SKIP: {}, file: {}, because extension: {}'.format(path, photo_file_name, extension))
            continue
        if args.dry_run:
            # sleep(0.1)
            continue

        try:
            photo_file = open("{}/{}".format(path, photo_file_name), mode='rb')
            photo_bytes = photo_file.read()
        except OSError as err:
            logging.error("Could not read file \'{0}\' -- {1}".format(photo_file_name, err))
            continue

        session.headers["X-Goog-Upload-File-Name"] = os.path.basename(photo_file_name)

        logging.info("Uploading photo -- \'{}\'".format(photo_file_name))

        upload_token = session.post('https://photoslibrary.googleapis.com/v1/uploads', photo_bytes)

        if (upload_token.status_code == 200) and (upload_token.content):

            create_body = json.dumps({"albumId": album_id, "newMediaItems": [
                {"description": "", "simpleMediaItem": {"uploadToken": upload_token.content.decode()}}]}, indent=4)

            resp = session.post('https://photoslibrary.googleapis.com/v1/mediaItems:batchCreate', create_body).json()

            logging.debug("Server response: {}".format(resp))

            if "newMediaItemResults" in resp:
                status = resp["newMediaItemResults"][0]["status"]
                if status.get("code") and (status.get("code") > 0):
                    logging.error("Could not add \'{0}\' to library -- {1}".format(os.path.basename(photo_file_name),
                                                                                   status["message"]))
                else:
                    logging.info("Added \'{}\' to library and album \'{}\' ".format(os.path.basename(photo_file_name),
                                                                                    album_name))
            else:
                logging.error(
                    "Could not add \'{0}\' to library. Server Response -- {1}".format(os.path.basename(photo_file_name),
                                                                                      resp))

        else:
            logging.error("Could not upload \'{0}\'. Server Response - {1}".format(os.path.basename(photo_file_name),
                                                                                   upload_token))

    try:
        del (session.headers["Content-type"])
        del (session.headers["X-Goog-Upload-Protocol"])
        del (session.headers["X-Goog-Upload-File-Name"])
    except KeyError:
        pass


def main(args):
    root_dir = os.path.expanduser(args.root_dir)

    logging.info('Expand: {}'.format(os.path.expanduser(root_dir)))
    logging.info('Abs path: {}'.format(os.path.abspath(root_dir)))

    filecounter = 0
    for _ in os.walk(root_dir):
        filecounter += 1
    if filecounter == 0:
        logging.warning('No files to upload.')
        exit(0)

    logging.info('Creating session for upload...')
    session = get_authorized_session(args.auth_file)

    for path, subdirs, files in tqdm(os.walk(root_dir), total=filecounter, desc='Dirs', leave=False):
        logging.info('Root: {}'.format(path))
        if files:
            _, album_name = os.path.split(path)
            if album_name in args.excludes:
                logging.info('SKIP album name: {}'.format(album_name))
                continue

            logging.info('Album name: {}'.format(album_name))
            upload_photos(session, path, files, album_name, args)

    # As a quick status check, dump the aglbums and their key attributes
    print("{:<60} | {:>8} | {} ".format("PHOTO ALBUM", "# PHOTOS", "IS WRITEABLE?"))

    for a in getAlbums(session):
        print(
            "{:<60} | {:>8} | {} ".format(a["title"], a.get("mediaItemsCount", "0"), str(a.get("isWriteable", False))))


def print_report():
    print('*' * 60)
    for k in sorted(REPORT.keys()):
        print('{:<60}: {:>8}'.format(k, REPORT[k]))


if __name__ == '__main__':
    args = parse_args()

    tqdm_handler = TqdmHandler()
    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    log_level = levels[min(len(levels) - 1, args.verbose)]  # capped to number of levels

    tqdm_handler.setLevel(log_level)
    logging.basicConfig(format='%(asctime)s - %(levelname)8s - %(name)s - %(message)s',
                        # filename=args.log_file,
                        level=logging.DEBUG,
                        handlers=[tqdm_handler])
    try:
        main(args)
    except KeyboardInterrupt as e:
        logging.debug('Ctrl-C pressed')
        exit(1)
    finally:
        print_report()
    logging.info('Done.')
