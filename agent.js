
let server_address = "ws://localhost:8081"

// sen button event container 
function send_btn_cb(socket)
{
    console.log("Send Button Clicked");
    
    const ei = document.getElementById("ei-line-edit");
    const pi = document.getElementById("pi-line-edit");

    if(ei.value && pi.value)
    {
        let login_data = {
            email:ei.value,
            password:pi.value,
        };

        socket.send(JSON.stringify(login_data));
    }
    else
    {
        alert("Please insert the your login data !!");
    }
}

function create_login_page(socket)
{
    const container = document.getElementById("container");
    container.innerHTML = "";

    // email input line edit
    const ei = document.createElement("input");
    ei.type = "text";
    ei.id = "ei-line-edit";
    ei.style.marginRight = "5px";

    // password input line edit
    const pi = document.createElement("input");
    pi.type = "password";
    pi.id = "pi-line-edit";
    pi.style.marginRight = "5px";


    // submit button 
    const sb = document.createElement("button");
    sb.innerText = "Send";
    sb.id = "sb-button";
    sb.style.marginRight = "5px";
    sb.addEventListener("click", function (event){
        send_btn_cb(socket);
    });

    // add to main container
    container.appendChild(ei);
    container.appendChild(pi);
    container.appendChild(sb);
}


function create_main_page(socket_id, data_obj)
{
    const container = document.getElementById("container");
    container.innerHTML = "";

    const a_label = document.createElement("a");
    a_label.innerHTML = data_obj.name + " " + data_obj.last_name;
    a_label.style.marginRight = "5px";

    container.appendChild(a_label);
}   

function create_websocket ()
{
    const socket = new WebSocket(server_address);

    socket.onopen = () => {
        console.log("WS Connection Created.. ACK sending..");
        let ws_ack = {
            ws:"ack",
        };

        socket.send(JSON.stringify(ws_ack));
    };

    socket.onmessage = (event) => {
        const obj = JSON.parse(event.data);
        if(obj.state == "login"){
            create_login_page(socket);

            let lpc_ack = {
                lpc:"ack",
            };

            socket.send(JSON.stringify(lpc_ack));
        }

        else if(obj.state == "login_ok")
        {
            create_main_page(socket, obj);
        }


        console.log(obj.state);
    };

    socket.onclose = () => {
        console.log("Connection Closed");
    };
}


// Create the websocket
create_websocket();


