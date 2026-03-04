import json

 # tshark -r evidence.pcap -Y "bittorrent.piece.data and ip.src == 34.10.241.248" -T json > pieces.json

with open('pieces.json') as f:
    packets = json.load(f)

pieces = {}

for packet in packets:
    bt = packet['_source']['layers']['bittorrent']['bittorrent.msg']
    index = bt['bittorrent.piece.index']
    begin = bt['bittorrent.piece.begin']
    hex_data = bt['bittorrent.piece.data']
    data = bytes.fromhex(hex_data.replace(':', ''))
    pieces[(int(index,16), int(begin,16))] = data

with open('output.bin', 'wb') as f:
    for key in sorted(pieces):
        f.write(pieces[key])
