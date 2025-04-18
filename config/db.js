const mongoose = require('mongoose');

const connectDB = async () => {
    mongoose.connect('mongodb+srv://username:root@cluster0.tcbgdea.mongodb.net/authlogin')
      .then(() => {
        console.log("mongodb+srv://user:root@cluster0.qcowr2v.mongodb.net/test?retryWrites=true&w=majority")
      })
      .catch(err => console.log(err))
  };

module.exports = connectDB;
