"""Regenerate synthetic, Apache-2.0 example evidence. Requires Python3 and Pillow12.3.
No user evidence is read. Output overwrites only named fixtures in examples/.
"""
from pathlib import Path
from PIL import Image, ImageDraw, PngImagePlugin
import json, hashlib
root = Path(__file__).resolve().parents[1]
examples = root / 'examples'
secrets = ['AUTH_SEED_0123456789', 'COOKIE_SEED_0123456789', 'QUERY_SEED_0123456789', 'BODY_SEED_0123456789', 'EXTENSION_SEED_0123456789', 'LOG_SEED_0123456789', 'IMAGE_META_SEED_0123456789']
har = {'log': {'version': '1.2', 'creator': {'name': 'Synthetic browser', 'version': '1.0', 'comment': secrets[4]}, 'comment': secrets[4], 'entries': [{'startedDateTime': '2026-01-01T12:00:00.000Z', 'time': 112, 'comment': secrets[4], 'request': {'method': 'POST', 'url': 'https://example.test/api/items?token='+secrets[2]+'&page=1', 'httpVersion': 'HTTP/1.1', 'headers': [{'name': 'Authorization', 'value': 'Bearer '+secrets[0]}, {'name': 'Cookie', 'value': 'session='+secrets[1]}, {'name': 'Content-Type', 'value': 'application/json'}, {'name': 'X-Private-Debug', 'value': secrets[4]}], 'queryString': [{'name': 'token', 'value': secrets[2]}, {'name': 'page', 'value': '1'}], 'cookies': [{'name': 'session', 'value': secrets[1]}], 'postData': {'mimeType': 'application/json', 'text': json.dumps({'password': secrets[3], 'name': 'synthetic'})}, 'headersSize': -1, 'bodySize': 90}, 'response': {'status': 500, 'statusText': 'Internal Server Error', 'httpVersion': 'HTTP/1.1', 'headers': [{'name': 'Content-Type', 'value': 'application/json'}, {'name': 'Set-Cookie', 'value': 'session='+secrets[1]}], 'cookies': [{'name': 'session', 'value': secrets[1]}], 'content': {'size': 81, 'mimeType': 'application/json', 'text': json.dumps({'error':'synthetic failure','access_token': secrets[3]})}, 'redirectURL': '', 'headersSize': -1, 'bodySize': 81}, 'cache': {}, 'timings': {'send': 1, 'wait': 100, 'receive': 11}, '_debug': secrets[4]}]}}
(examples/'sample.har').write_text(json.dumps(har,indent=2)+'\n',encoding='utf-8')
(examples/'sample.log').write_text('2026-01-01T12:00:00Z ERROR request failed status=500\nAuthorization: Bearer '+secrets[0]+'\npassword='+secrets[5]+'\nContact: private@example.test (remove this manually before sharing)\n',encoding='utf-8')
image=Image.new('RGB',(640,280),'#f6f8fc'); draw=ImageDraw.Draw(image)
draw.rectangle((0,0,639,43),fill='#182b49'); draw.text((20,16),'Synthetic issue: request returned 500',fill='white')
draw.text((20,66),'Account token: visible synthetic screenshot secret',fill='#182b49')
draw.rectangle((20,94,470,127),fill='#ffd3c7'); draw.text((28,105),'SCREENSHOT_SEED_0123456789',fill='#5c1f13')
draw.text((20,160),'Review screenshot pixels and cover this token before export.',fill='#182b49')
metadata=PngImagePlugin.PngInfo(); metadata.add_text('Comment',secrets[6]);image.save(examples/'sample.png',pnginfo=metadata)
exif=Image.Exif();exif[0x010E]=secrets[6];image.save(examples/'sample.jpg',quality=90,exif=exif)
manifest={'schemaVersion':1,'purpose':'Synthetic debugging evidence; not real credentials.','secrets':secrets,'screenshotMask':{'x':20,'y':94,'width':451,'height':34},'manualLogValue':'private@example.test','files':[]}
for name in ['sample.har','sample.log','sample.png','sample.jpg']:
 b=(examples/name).read_bytes();manifest['files'].append({'name':name,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()})
(examples/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':'synthetic-fixtures-generated','files':len(manifest['files'])}))
