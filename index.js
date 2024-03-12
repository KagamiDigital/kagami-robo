require("dotenv").config();

const io = require("socket.io-client");

const socket = io(process.env.API_URL, {
  query: {
    apiKey: process.env.API_KEY,
  },
});

socket.on("connect", () => {
  console.log("Connected to server");
});
