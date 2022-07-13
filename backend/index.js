const express = require('express');

const app = express();
const PORT = 5000;

app.use(express.json());

app.use('/auth', require('./routes/auth'));
app.use('/posts', require('./routes/posts'));

app.listen(PORT, () => {
  console.log('listening on port 5000');
});
