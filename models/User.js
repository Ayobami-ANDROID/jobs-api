const bcrypt = require('bcryptjs')
const mongoose = require('mongoose')
const jwt = require('jsonwebtoken')

const userSchema = new mongoose.Schema({
    name:{
        type:String,
        required:[true,'please provide username'],
        minLength:3,
        maxLength:50,
    },
    email:{
        type:String,
        required:[true,'please provide email'],
        match:[/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,'please provide valid email'],
    //    unique:true
    },
    password:{
        type:String,
        required:[true,'please provide password'],
        minLength:6,
     
    }
})

userSchema.pre('save',async function(){
  const salt = await bcrypt.genSalt(10)
  this.password = await bcrypt.hash(this.password,salt)
})

userSchema.methods.createJWT = function(){
  return jwt.sign({userId:this._id,name:this.name},process.env.JWT_SECRET,{expiresIn:process.env.Jwt_LIFETIME})
}

userSchema.methods.comparePassword = async function(canditatePassword){
  const isMatch = await bcrypt.compare(canditatePassword,this.password)
  return isMatch 
}

// userSchema.pre('save',async function(){
//   this.salt = await bcrypt.genSalt(10)
//   this.password = await bcrypt.hash(this.password,salt)
// } )

// userSchema.methods.createJwt = function(){
//   return jwt.sign({userId:this._id,name:this.name},process.env.JWT_SECRET,{expiresIn:process.env.JWT_LIFETIME} )
// }
// userSchema.methods.comparePassword = async function(canditatePassword){
//  const isMatch = await bcrypt.compare(canditatePassword,this.password) 
//  return isMatch
// }
module.exports = mongoose.model('user',userSchema)