import express from 'express';

const app = express();

app.get('/', (req, res) => {
    res.send('../index.server.js');
});

app.listen(5000, () => {
    console.log('server listening on port 5000.');
});
