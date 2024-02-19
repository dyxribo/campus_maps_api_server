import express from 'express';

const app = express();

app.get('/', (req, res) => {
    res.send('<h1>hello from blaxstar!</h1>');
});

app.listen(5000, () => {
    console.log('server listening on port 5000.');
});
