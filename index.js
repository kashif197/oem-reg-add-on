require('nan')
const { decrypt } = require('./build/Release/decrypt.node')

const express = require('express')
const fileupload = require('express-fileupload')
const app = express()

app.use(fileupload())


app.put('/upload', (req, res) => {
    const dataFile = req.files.data
    const sessKeyFile = req.files.sessionkey
    const prvKeyFile = req.files.prvkey

    var dataPath = "C:\\Users\\Kay\\Documents\\Microsoft OEM Activation 3.0\\OEM Registration Pages Files\\files\\user\\userdata.blob"
    var sessionKeyPath = "C:\\Users\\Kay\\Documents\\Microsoft OEM Activation 3.0\\OEM Registration Pages Files\\files\\user\\sessionkey.blob"
    var prvKeyPath = "C:\\Users\\Kay\\Documents\\Microsoft OEM Activation 3.0\\OEM Registration Pages Files\\files\\user\\prvkey.blob"
    var destPath = "C:\\Users\\Kay\\Documents\\Microsoft OEM Activation 3.0\\OEM Registration Pages Files\\files\\user\\plain.xml"

    dataFile.mv('./data/' + dataFile.name, function (err, result) {
        if (err) throw err
        else {
            sessKeyFile.mv('./data/' + sessKeyFile.name, function (err, result) {
                if (err) throw err
                else {
                    prvKeyFile.mv('./data/' + prvKeyFile.name, function (err, result) {
                        if (err) throw err
                        else {
                            console.log('here')
                            decrypt(dataPath, sessionKeyPath, prvKeyPath, destPath)
                            res.send({
                                status: true
                            })
                        }
                    })
                }
            })
        }
    })
})

const PORT = 5000

app.listen(PORT, () => console.log('Server Running On Port'))