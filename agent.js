
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

function delete_todo_cb(socket_id, btn_id)
{
    console.log("Todo Delete Button " + btn_id + " Clicked !!!");

    let todo_deleted_cmd = {
        type:"data",
        cmd:200, // delete
        todo_id:btn_id,
    };

    console.log("Todo " + btn_id + " Delete Command Sended !!");

    socket_id.send(JSON.stringify(todo_deleted_cmd));
}


function blockSleep(ms) {
  const end = Date.now() + ms;
  while (Date.now() < end) {}
}

function create_main_page(socket_id, data_obj)
{
    const container = document.getElementById("container");
    container.innerHTML = "";

    const header_div = document.createElement("div");
    header_div.id = "header-div";
    const body_div = document.createElement("div");
    body_div.id = "body-div";

    header_div.style.backgroundColor = "#6bc1f3ff";
    header_div.style.padding = "3px";
    header_div.style.borderRadius = "3px";

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

blockSleep(10);

    console.log("todo list req sended");

    let get_todo_list_req = {
        type:"data",
        request:101, //get todo list
    };

    socket_id.send(JSON.stringify(get_todo_list_req));
}   

function create_todo_list(socket_id, obj)
{
    const body_div = document.getElementById("body-div");
    body_div.innerHTML = "";
    body_div.style.display = "flex";
    body_div.style.flexDirection = "column";
    body_div.style.gap = "10px";
    body_div.style.marginTop = "10px";
    body_div.style.backgroundColor = "#d0d3d4ff";
    body_div.style.padding = "3px";
    body_div.style.borderRadius = "3px";

    const mlength  = obj.todo_list.length / 3;
    console.log("length:" + mlength);

    for (let i = 0; i<mlength; i++) 
    {
        const xdiv = document.createElement("div");
        xdiv.style.backgroundColor = "#abc1d8ff"
        xdiv.style.margin = "3px";
        xdiv.style.padding = "3px";
        xdiv.style.borderRadius = "3px";
        xdiv.style.display = "flex";
        xdiv.style.justifyContent = "space-between";

        const adata = document.createElement("a");
        adata.innerHTML = obj.todo_list[(i*3) + 1] + " - " + obj.todo_list[(i*3) + 2] ;
        xdiv.appendChild(adata);

        const delete_btn = document.createElement("button");
        delete_btn.innerText = "Delete";
        delete_btn.id = "delete-button-" + i;
        delete_btn.addEventListener("click", function (event, id){
            delete_todo_cb(socket_id, i);
        });

        xdiv.appendChild(delete_btn);

        body_div.appendChild(xdiv);
    }
}

function create_websocket ()
{
    const socket = new WebSocket(server_address);

    socket.onopen = () => {
        console.log("WS Connection Created.. ACK sending..");
        let ws_ack = {
            ws:"ack",
        };

        create_login_page(socket);
        socket.send(JSON.stringify(ws_ack));
        
    };

    socket.onmessage = (event) => {
        const obj = JSON.parse(event.data);

        if(obj.state == "login_ok")
        {
            create_main_page(socket, obj); 
        }
        else if(obj.type == "data" && obj.response == 101)
        {
            create_todo_list(socket, obj); 
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


