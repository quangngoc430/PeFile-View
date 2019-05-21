const express = require('express');
const { exec } = require('child_process');
var engine = require('consolidate');
const path = require('path');
const fs = require('fs');
const opn = require('opn');

const port = 3000;

const app = express();

app.set('views', __dirname + '/views');
app.engine('html', engine.mustache);
app.set('view engine', 'html');

app.get('/data', (req, res) => {
    exec(`python code.py ${process.argv[2]}`, (err, stprdout, stderr) => {
        if (err) {
            console.log('error');
            return;
        }

        const dataBuffer = fs.readFileSync('data.json');
        const data = JSON.parse(dataBuffer.toString());
        res.json(data);
    });
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname+'/views/index.html'));
});

app.listen(port, function() {
    console.log(`Server listening on port ${port}`);
    opn('http://localhost:3000');
})
