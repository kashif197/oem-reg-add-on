require('nan')
const { decrypt } = require('./build/Release/decrypt.node')

const express = require('express')
const fileupload = require('express-fileupload')
const app = express()


app.use(fileupload())

app.post('/upload', (req, res) => {
    const dataFile = req.files.data
    const sessKeyFile = req.files.sessionkey
    const prvKeyFile = req.files.prvkey

    dataFile.mv('./data/' + dataFile.name, function (err, result) {
        if (err) throw err
        else {
            sessKeyFile.mv('./data/' + sessKeyFile.name, function (err, result) {
                if (err) throw err
                else {
                    prvKeyFile.mv('./data/' + prvKeyFile.name, function (err, result) {
                        if (err) throw err
                        else {
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

const PORT = process.env.PORT || 5000

app.listen(PORT, () => console.log('Server Running On Port'))