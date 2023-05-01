const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt')
const fs = require('fs')
const app = express();
const port = 3000;
const version = '1.0.0'
//Future code
//JSON.parse(fs.readFileSync(`/package.json`)).version
//console.log(req.ip)

app.use(cors());

// Configuring body parser middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

//Log Handler
async function logAction(log){
    let date = Date()
    let data = fs.readFileSync(`./logs/April2023`, 'utf-8')
    fs.writeFileSync(`./logs/April2023`, `${data}\n${date}: ${log}`)
}

//Login
app.post('/login', (req, res) => {
    const body = req.body;
    logAction(`Login Attempt: ${body.username}`)
    if(fs.existsSync(`./passwords/${body.username}.json`)){
        let rawData = fs.readFileSync(`./passwords/${body.username}.json`)
        let jsonData = JSON.parse(rawData)
        bcrypt.compare(body.password, jsonData.password, function(err, result) {
            if(result === true){
                res.send('{ "status": 200, "response": "Login successful" }')
                fs.writeFileSync(`./sessions/${body.sessionID}.json`, `{ "user": "${body.username}", "password": "${body.password}" }`)
                logAction(`Login Success: ${body.username}`)
                logAction(`New Session: ${body.sessionID}`)
            }
            if(result === false){
                res.send('{ "status": 400, "response": "Password is incorrect" }')
                logAction(`Login Password Incorrect: ${body.username}`)
            }
        })
    } else {
        res.send('{ "status": 401, "response": "Account does not exist" }')
        logAction(`Non-Existent Account: ${body.username}`)
    }
});

//Security
app.post('/passwordcheck', (req, res) => {
    const body = req.body;
    logAction(`Password Check: ${body.sessionID}`)
    if(fs.existsSync(`./sessions/${body.sessionID}.json`)){
        let rawData = fs.readFileSync(`./sessions/${body.sessionID}.json`)
        let jsonData = JSON.parse(rawData)
        if(fs.existsSync(`./passwords/${jsonData.user}.json`)){
            let rawACData = fs.readFileSync(`./passwords/${jsonData.user}.json`)
            let jsonACData = JSON.parse(rawACData)
            bcrypt.compare(jsonData.password, jsonACData.password, function(err, result) {
                if(result === true){
                    res.send('{ "status": 2010, "response": "Password check is valid" }')
                    logAction(`Password Check Valid: ${jsonData.user}`)
                }
                if(result === false){
                    res.send('{ "status": 2012, "response": "Password check is invalid" }')
                    fs.unlinkSync(`./sessions/${body.sessionID}.json`)
                    logAction(`Password Check Invalid: ${jsonData.user}`)
                    logAction(`Session Terminated: ${body.sessionID}`)
                }
            })
        } else {
            res.send('{ "status": 2011, "response": "Username check is invalid" }')
            fs.unlinkSync(`./sessions/${body.sessionID}.json`)
            logAction(`Password Check Invalid: ${jsonData.user}`)
            logAction(`Session Terminated: ${body.sessionID}`)
        }
    } else {
        res.send('{ "status": 2013, "response": "Session invalid" }')
    }
})

//OTP Regen & Handling
async function otpRegen(){
    let dir = fs.readdirSync(`./otp/`)
    dir.forEach(async (element) => {
        let otpChars = '123456789'
        let otpLength = 5
        var otpID = ""
        for (var i = 0; i <= otpLength; i++) {
            var randomNumberOTP = Math.floor(Math.random() * otpChars.length);
            otpID += otpChars.substring(randomNumberOTP, randomNumberOTP +1);
        }
        fs.writeFileSync(`./otp/${element}`, `{ "OTP": ${otpID} }`)
    })
}
setInterval(otpRegen, 30*1000)
app.post('/otpcheck', (req, res) => {
    const body = req.body;
    logAction(`OTP Check: ${body.sessionID}`)
    let rawData = fs.readFileSync(`./sessions/${body.sessionID}.json`)
    let jsonData = JSON.parse(rawData)
    if(fs.existsSync(`./otp/${jsonData.user}.json`)){
        let rawOTP = fs.readFileSync(`./otp/${jsonData.user}.json`)
        let jsonOTP = JSON.parse(rawOTP)
        logAction(`OTP Check Account Exists: ${jsonData.user}`)
        if(Number(body.otp) === jsonOTP.OTP){
            res.send('{ "status": 2014, "response": "OTP check is valid" }')
            logAction(`OTP Check Valid: ${body.sessionID}`)
            logAction(`Admin Mode Enabled: ${jsonData.user}`)
        } else {
            res.send('{ "status": 2015, "response": "OTP check is invalid" }')
            logAction(`OTP Check Invalid: ${body.sessionID}`)
            logAction(`OTP Check Fail: ${jsonData.user}`)
        }
    } else {
        res.send('{ "status": 2016, "response": "OTP account not found" }')
        logAction(`OTP Check Invalid: ${body.sessionID}`)
    }
})

//Logout
app.post('/logout', (req, res) => {
    const body = req.body;
    logAction(`Session Termination Request: ${body.sessionID}`)
    if(fs.existsSync(`./sessions/${body.sessionID}.json`)){
        fs.unlinkSync(`./sessions/${body.sessionID}.json`)
        logAction(`Session Terminated: ${body.sessionID}`)
    } else {
        logAction(`Session Unable to Terminate: ${body.sessionID}`)
    }
});

//Shutdown
app.post('/shutdown', (req, res) => {
    const body = req.body;
    logAction(`Session Termination Request: ${body.sessionID}`)
    if(fs.existsSync(`./sessions/${body.sessionID}.json`)){
        fs.unlinkSync(`./sessions/${body.sessionID}.json`)
        logAction(`Session Terminated: ${body.sessionID}`)
    } else {
        logAction(`Session Unable to Terminate: ${body.sessionID}`)
    }
});




app.listen(port, () => console.log(`Hash-API V-${version} listening on port ${port}!`))