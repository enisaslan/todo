
let server_address = "ws://localhost:8081"

// sen button event container 
function send_btn_cb()
{
    console.log("Send Button Clicked");
}

function create_login_page()
{
    const container = document.getElementById("container");
    container.innerHTML = "";

    // email input line edit
    const ei = document.createElement("input");
    ei.type = "text";
    ei.id = "ei-line-edit";

    // password input line edit
    const pi = document.createElement("input");
    pi.type = "password";
    pi.id = "pi-line-edit";

    // submit button 
    const sb = document.createElement("button");
    sb.innerText = "Send";
    sb.id = "sb-button";
    sb.addEventListener("click", send_btn_cb);

    // add to main container
    container.appendChild(ei);
    container.appendChild(pi);
    container.appendChild(sb);

}


function create_websocket ()
{
    const socket = new WebSocket(server_address);

    socket.onopen = () => {
        console.log("WS Connection Created.. ACK sending..");
        socket.send("{ws:ack}\0");
    };

    socket.onmessage = (event) => {
        const obj = JSON.parse(event.data);
        if(obj.state == "login"){
            create_login_page();

            socket.send("{lpc:ack}\0");
        }
        console.log(obj.state);
    };

    socket.onclose = () => {
        console.log("Connection Closed");
    };
}


// Create the websocket
create_websocket();


