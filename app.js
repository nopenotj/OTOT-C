const express = require('express')
const { Authenticator, Permission } = require('./auth')
const app = express()
const port = 3000
const JWT_SECRET = 'secret'
app.use(express.json())

// MOCK DB INSTANCE
const db = {
    data: [
        {id:0, user:"test", pass:"1234"}
    ],
    get_user_by_name: (name) => { for (const user of db.data) if (user.user == name) return user},
    get_user_by_id: (id) => data[id]
}

const auth = new Authenticator(db, JWT_SECRET)

// Create some roles with associated permissions
auth.add_role('admin').push(new Permission('*','READ'))
auth.add_role('author').push(new Permission('books','READ'))

// Assign userid 0 to admin
auth.assign_role(0,'author')

// PROTECTED RESOURCES
app.get('/books', auth.authenticate([new Permission('books','READ')], (req, res) => res.send('Here are your books')))
app.get('/water', auth.authenticate([new Permission('water','READ')], (req, res) => res.send('Here is your water')))

// LOGIN ROUTE
app.post('/login', (req, res) => {
    const {user, pass} = req.body
    // 400: BAD REQUEST
    if(user == undefined || pass == undefined) return res.status(400).send()

    try {
        res.send({ token: auth.get_token(user,pass) })
    // 401: If auth fails
    } catch (err){ return res.status(401).send() }
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})