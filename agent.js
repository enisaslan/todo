
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
            type:"data",
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

function create_new_todo_cb(socket_id)
{
    console.log("New Todo Create Button Clicked !!!");
}

function create_main_page(socket_id, data_obj)
{
    const container = document.getElementById("container");
    container.innerHTML = "";

    const header_div = document.createElement("div");
    const body_div = document.createElement("div");

    header_div.style.backgroundColor = "#6bc1f3ff";
    header_div.style.padding = "3px";

    const user_a = document.createElement("a");
    user_a.innerHTML = data_obj.name + " " + data_obj.last_name;
    user_a.style.marginRight = "10px";

    const new_todo = document.createElement("button");
    new_todo.innerText = "New Todo";
    new_todo.id = "new-todo-button";
    new_todo.style.marginRight = "10px";
    new_todo.addEventListener("click", function (event){
        create_new_todo_cb(socket_id);
    });

    const total_todo = document.createElement("a");
    total_todo.innerHTML = "| Active ToDo Count: " + 
                    data_obj.active_count + 
                    " | Completed ToDo Count: " + 
                    data_obj.completed_count + " | ";
    total_todo.style.marginRight = "10px";

    header_div.appendChild(user_a);
    header_div.appendChild(total_todo);
    header_div.appendChild(new_todo);

    container.appendChild(header_div);
    container.appendChild(body_div);

    let main_page_ack = {
        type:"ack",
        state:"main_page_created",
    };

    console.log("ack sended");

    socket_id.send(JSON.stringify(main_page_ack));
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
        if(obj.state == "login")
        {
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
        else
        {
            console.log(" Unknown Data Received ");
        }
    };

    socket.onclose = () => {
        console.log("Connection Closed");
    };
}


// Create the websocket
create_websocket();


