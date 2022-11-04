const jwt = require('jsonwebtoken');

class Authenticator {
    constructor(repo, jwt_secret) {
        // repo must implement a get_user_by_name and get_user_by_id functions
        this.repo = repo
        this.roles = {}
        this.user_roles = {}
        // Possible Extension: allow class to read in a private key file
        this.jwt_secret = jwt_secret
    }
    authenticate(perms, f) {
        return (...args) => {
            const [req,res] = args; 
            try {
                const token = req.get("Authorization").split(" ")[1]
                const {userid, exp} = jwt.verify(token,this.jwt_secret)
                // Possible Extension: exp contains the epoch time when token expires.
                if (!this.verify(perms, this.get_permissions(userid))) return res.status(403).send()
            } catch(err) {
                return res.status(401).send()
            }

            return f(...args)
        }
    }
    verify(required_permissions, available_permissions) {
        for(const p of required_permissions) {
            if(!p.is_satisfied_by(available_permissions)) return false
        }
        return true
    }
    get_permissions(userid) {
        return this.roles[this.user_roles[userid]]
    }
    get_token(user, pass) {
        const u = this.repo.get_user_by_name(user)
        if(u == undefined || u.pass != pass) throw "Wrong Password"
        return jwt.sign({userid:u.id}, this.jwt_secret, { expiresIn: '1h' });
    }
    add_role(role_name) {
        this.roles[role_name] = []
        return this.roles[role_name]
    }
    get_role(role_name) {
        return this.roles[role_name]
    }
    assign_role(userid, role_name) {
        this.user_roles[userid] = role_name 
    }
}

class Permission {
    constructor(resource, action){
        this.resource = resource
        this.action = action
    }
    is_satisfied_by(permission_list) {
        for(const p of permission_list){
            if (p.resource == '*' || p.resource == this.resource) 
                if(p.action == this.action) 
                    return true
        }
        return false
    }
}
module.exports = {
    Authenticator,
    Permission
}