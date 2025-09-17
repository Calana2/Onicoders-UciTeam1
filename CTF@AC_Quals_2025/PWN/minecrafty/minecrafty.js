// npm install minecraft-protocol
// node walker.js

const mc = require('minecraft-protocol')
const readline = require('readline')
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false,
  prompt: 'Enter a message> '
})

var entityId = 0
var nextPosition = { 'x': 100, 'y': 100, 'z': 100 }
let walkInterval = null

const [,, host, port, username] = process.argv
if (!host || !port) {
  console.error('Usage: node client_chat.js <host> <port> <username>')
  console.error('Usage (offline mode): node client_chat.js <host> <port> offline')
  process.exit(1)
}

const client = mc.createClient({
  host,
  port,
  username,
  auth: 'offline',
})

// Boilerplate
client.on('disconnect', function (packet) {
  console.log('Disconnected from server : ' + packet.reason)
})

client.on('end', function () {
  console.log('Connection lost')
  process.exit()
})

client.on('error', function (err) {
  console.log('Error occurred')
  console.log(err)
  process.exit(1)
})

client.on('connect', () => {
  const ChatMessage = require('prismarine-chat')(client.version)

  console.log('Connected to server')
  setTimeout(() => {
    rl.prompt()
   }, 2500);

  client.on('playerChat', function ({ senderName, plainMessage, unsignedContent, formattedMessage, verified }) {
    let content

    const allowInsecureChat = true

    if (formattedMessage) content = JSON.parse(formattedMessage)
    else if (allowInsecureChat && unsignedContent) content = JSON.parse(unsignedContent)
    else content = { text: plainMessage }

    const chat = new ChatMessage(content)
    console.log(senderName, { trugie: 'Verified:', false: 'UNVERIFIED:' }[verified] || '', chat.toAnsi())
  })
})

// Send the queued messages
const queuedChatMessages = []
client.on('state', function (newState) {
  if (newState === mc.states.PLAY) {
    queuedChatMessages.forEach(message => client.chat(message))
    queuedChatMessages.length = 0
  }
})

// Listen for messages written to the console, send them to game chat
rl.on('line', function (line) {
  if (line === '') {
    return
  } else if (line === '/quit') {
    console.info('Disconnected from ' + host + ':' + port)
    client.end()
    return
  } else if (line === '/end') {
    console.info('Forcibly ended client')
    process.exit(0)
  } else if (line === "!walk") {
    console.info('Walking....')
    if (walkInterval) clearInterval(walkInterval)
    walkInterval = setInterval(() => {
      if (nextPosition.x != 69400) { nextPosition.x += 100 }
      else if (nextPosition.y != 69400) { nextPosition.y += 100 }
      else if (nextPosition.z != 69400) { nextPosition.z += 100 }
      console.log(`[CLIENT] Set Player Position and Rotation: ${nextPosition.x}, ${nextPosition.y}, ${nextPosition.z}`)
      client.write('position_look', {
        x: nextPosition.x,
        y: nextPosition.y,
        z: nextPosition.z,
        yaw: 0,
        pitch: 0,
        onGround: true
      })
       if (nextPosition.x === 69400 && nextPosition.y === 69400 && nextPosition.z === 69400) {
         
      client.write('position_look', {
        x: nextPosition.x + 20,
        y: nextPosition.y + 20,
        z: nextPosition.z + 20,
        yaw: 0,
        pitch: 0,
        onGround: true
      })

      console.log("[*] The bot has arrived!")
      setTimeout(() => {
       if (!client.chat) {
        queuedChatMessages.push("!flag")
       } else {
         client.chat("!flag")
       }
      }, 1000);
      clearInterval(walkInterval)
      walkInterval = null
    }
    }, 50)
    return
  }
  if (!client.chat) {
    queuedChatMessages.push(line)
  } else {
    client.chat(line)
  }
})

client.on('packet', (data, meta) => {
  if (meta.name === 'login' && data.entityId) {
    entityId = data.entityId
    console.log('[*] Login success')
  }
})

client.on('spawn_position', (packet) => {
  console.log("[SERVER] Spawn Entity: ")
  console.log(packet,"\n")
})

client.on('position', (packet) => {
  console.log("[SERVER] Synchronize Player Position: ")
  console.log(packet,"\n")
  // 1) Confirm teleport
  packet = {teleportId: packet.teleportId}
  console.log("[CLIENT] Confirm Teleportation:\n",packet,"\n")
  client.write('teleport_confirm', {
    teleportId: packet.teleportId
  })
  // 2) Confirm position
  client.write('position_look', {
    x: nextPosition.x,
    y: nextPosition.y,
    z: nextPosition.z,
    yaw: packet.yaw,
    pitch: packet.pitch,
    onGround: true
  })
})

