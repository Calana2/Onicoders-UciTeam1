# minecrafty

<img width="1536" height="1024" alt="Copilot_20250916_202348" src="https://github.com/user-attachments/assets/12b8ef1d-f085-43ac-bb2e-567783227169" />

Mi reto favorito en este CTF.

En `game/chat.go`:
```go
	switch string(message) {
		case "!flag":
			x := int32(player.Position[0])
			y := int32(player.Position[1])			
			z := int32(player.Position[2])
			
			if x != 69420 || y != 69420 || z != 69420 {		
				c.SendPlayerChat(
				player.UUID,
				0,
				signature,
				&sign.PackedMessageBody{
					PlainMsg: fmt.Sprintf("ctf{try_harder}  Your Position: %d %d %d  Expected Position: 69420 69420 69420", x, y, z),
					Timestamp: timestamp,
					Salt:      int64(salt),
					LastSeen:  []sign.PackedSignature{},
				},
				nil,
				&sign.FilterMask{Type: 0},
				&chatType,
				)
			} else {
				c.SendPlayerChat(
				player.UUID,
				0,
				signature,
				&sign.PackedMessageBody{
					PlainMsg: "ctf{redacted}",
					Timestamp: timestamp,
					Salt:      int64(salt),
					LastSeen:  []sign.PackedSignature{},
				},
				nil,
				&sign.FilterMask{Type: 0},
				&chatType,
				)
			}
````

Nos dan la flag si escribimos `!flag` en el chat y nuestro jugador esta en las coordenadas `{ 69420 , 69420 , 69420 }`.

En retos parecidos suelen decir que no es necesario instalar Minecraft para conectarse y es cierto,en mi caso use `nodejs` y el modulo `minecraft-protocol`, aunque creo que ademas con `mineflayer` pudo haber sido mas facil.

En el repositorio de `minecraft-protocol` encontre un [bot basico para interactuar con el chat](https://github.com/PrismarineJS/node-minecraft-protocol/blob/master/examples/client_chat/client_chat.js) y lo modifique un poco.

Estuve revisando en `node_modules/minecraft-protocol/` los eventos y leyendo sobre el protocolo en https://minecraft.wiki/w/Minecraft_Wiki:Protocol_documentation

## Paquetes del protocolo de Minecraft (Basico)

- El paquete `Login` es enviado por el servidor cuando hay un inicio de sesion exitoso (en el modulo el evento se llama `login`)
<img width="1147" height="562" alt="2025-09-16-201447_1147x562_scrot" src="https://github.com/user-attachments/assets/d2d5d9a5-d256-468c-86a7-d5b064d5d7ab" />

- El paquete `Spawn Entity` es enviado por el servidor cuando una entidad es creada (en el modulo el evento se llama `spawn_position`)
<img width="1077" height="478" alt="2025-09-16-183759_1077x478_scrot" src="https://github.com/user-attachments/assets/2a959bb5-a88a-47bc-8c9a-fe593c429bfe" />

- El paquete `Synchronize Player Position` es enviado por el servidor durante login, uso de enderpearl o posicion invalida. **El servidor ignorara todos los paquetes de movimientos del cliente hasta que el cliente envie un paquete ` Confirm Teleportation` con el mismo ID**. (en el modulo el evento se llama `position`)
<img width="1151" height="557" alt="2025-09-16-184032_1151x557_scrot" src="https://github.com/user-attachments/assets/7e7e7176-1eb8-45e4-b484-34a0cd9a4e69" />

- El paquete `Confirm Teleportation` ya mencionado, es enviado como confirmacion de `Synchronize Player Position`. (en el modulo el evento se llama `teleport_confirm`)
<img width="1159" height="241" alt="2025-09-16-184643_1159x241_scrot" src="https://github.com/user-attachments/assets/aba6c578-59b0-44b5-87d4-1dd42b3419a8" />

- El paquete `Set Player Position and Rotation` actualiza la posicion XYZ del jugador en el servidor y la direccion a la que esta mirando (en el modulo el evento supongo que sea `position_look`)
<img width="877" height="289" alt="2025-09-16-194326_877x289_scrot" src="https://github.com/user-attachments/assets/1f254512-6795-465b-ad11-da8c79e2d9fd" />

<img width="678" height="367" alt="2025-09-16-195552_678x367_scrot" src="https://github.com/user-attachments/assets/b610ff2d-b442-47c4-ba25-1e6952236796" />

##
Lo que debemos hacer es:
1. Responder a los `Synchronize Player Position` con `Confirm Teleportation` (ya mostrado en las imagenes).
2. Enviar paquetes `Set Player Position and Rotation` aumentando la distancia en 100 unidades en cada iteracion.
3. Escribir `!flag` en el chat.

 No podemos teletransportarnos directamente a las coordenadas porque en `world/tick.go`:
```go
			distance := math.Sqrt(delta[0]*delta[0] + delta[1]*delta[1] + delta[2]*delta[2])
			if distance > 100 {
				// You moved too quickly :( (Hacking?)
				teleportID := c.SendPlayerPosition(p.Position, p.Rotation)
				p.teleport = &TeleportRequest{
					ID:       teleportID,
					Position: p.Position,
					Rotation: p.Rotation,
				}
			} else if inputs.Position.IsValid() {
				p.pos0 = inputs.Position
				p.rot0 = inputs.Rotation
				p.OnGround = inputs.OnGround
			} else {
				w.log.Info("Player move invalid",
					zap.Float64("x", inputs.Position[0]),
					zap.Float64("y", inputs.Position[1]),
					zap.Float64("z", inputs.Position[2]),
				)
				c.SendDisconnect(chat.TranslateMsg("multiplayer.disconnect.invalid_player_movement"))
			}
		}
```

El programa revisa si te mueves mas de 100 unidades en un tick (unidad basica de tiempo) y si lo haces te envia un `Synchronize Player Position` con tu posicion actual.

### Exploit
```js
// npm install minecraft-protocol
// npm install mineflayer
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
```

<img width="568" height="216" alt="2025-09-16-202328_568x216_scrot" src="https://github.com/user-attachments/assets/f5ced1a9-43b0-4d92-9a47-6a020efdcbe0" />

<img width="925" height="290" alt="2025-09-16-202208_925x290_scrot" src="https://github.com/user-attachments/assets/561332bf-8f83-4e78-8890-d64d2d928516" />


`ctf{72b79a618cd6c995584d8971eba740f8597661a6c3806f6d36a6b59dca110071}`


  
