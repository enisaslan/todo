let g_token = "";
let server_address = "ws://localhost:8081"

function connection_error()
{
    const container = document.getElementById("container");
    container.innerHTML = "<h2 class='connection-error'> WebSocket Connection Not Established !!!</h2>";
}
connection_error();

// sen button event container 
function send_btn_cb(socket)
{
    console.log("Send Button Clicked");
    
    const ei = document.getElementById("ei-line-edit");
    const pi = document.getElementById("pi-line-edit");

    if(ei.value && pi.value)
    {
        let login_data = {
            protocol:4,
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
    ei.style.margin = "5px";
    ei.style.maxWidth = "150px";
    ei.style.height = "20px"
    ei.value = "enis.aslan";

    // password input line edit
    const pi = document.createElement("input");
    pi.type = "password";
    pi.id = "pi-line-edit";
    pi.style.margin = "5px";
    pi.style.height = "20px"
    pi.style.maxWidth = "150px";
    pi.value = "ee12aa34"

    // submit button 
    const sb = document.createElement("button");
    sb.innerText = "Send";
    sb.id = "sb-button";
    sb.style.margin = "5px";
    sb.style.height = "25px"
    sb.style.width = "100px"
    sb.style.maxWidth = "100px";
    sb.addEventListener("click", function (event){
        send_btn_cb(socket);
    });

    const m_div = document.createElement("div");


    // add to main container
    m_div.appendChild(ei);
    m_div.appendChild(pi);
    m_div.appendChild(sb);

    m_div.style.display = "flex";
    m_div.style.flexDirection = "column";
    m_div.style.width = "180px";
    m_div.style.height = "130px";
    m_div.style.border = "solid 1px";
    m_div.style.backgroundColor = "#479cceff";
    m_div.style.alignItems = "center";
    m_div.style.justifyContent = "center";
    m_div.style.borderRadius = "5px";

    container.style.display = "flex";
    container.style.justifyContent = "center";
    container.style.alignItems = "center";
    container.style.height = "100vh";
    

    container.appendChild(m_div);
}

function create_new_todo_send_cb(socket)
{

    const t_title = document.getElementById("todoTitle");
    const t_details = document.getElementById("todoDetails");

    if((t_details.value) && (t_title.value))
    {
        let new_todo_data = {
            protocol:12, // new todo
            token:g_token,
            summary:t_title.value,
            details:t_details.value
        };

        socket.send(JSON.stringify(new_todo_data));
    }
    else
    {
        alert("Please insert the your login data !!");
    }
    console.log("send button clicked !!" + t_title.value + " - " + t_details.value);

}


function create_new_todo_cb(socket_id)
{
    const modal_is_contain = document.getElementById("newModalForm");
    if(modal_is_contain)
    {
        const t_title = document.getElementById("todoTitle");
        t_title.value = "";

        const t_details = document.getElementById("todoDetails");
        t_details.value = "";

        modal_is_contain.style.display = "block";
    }
    else
    {
        const modal = document.createElement("div");
        modal.classList.add("modal");
        modal.id = "newModalForm";

        const modal_content = document.createElement("div");
        modal_content.classList.add("modal-content");

        const header_text = document.createElement("h3");
        header_text.innerHTML = "New Todo";

        const summary = document.createElement("input");
        summary.type = "text";
        summary.id = "todoTitle";
        summary.placeholder = "Summary";

        const details = document.createElement("input");
        details.type = "text";
        details.id = "todoDetails";
        details.placeholder = "Details";

        const button_group = document.createElement("div");

        const button_submit = document.createElement("button");
        button_submit.id = "submitBtn";
        button_submit.classList.add("btn-submit");
        button_submit.innerText = "Send";

        const button_close = document.createElement("button");
        button_close.id = "closeBtn";
        button_close.classList.add("btn-close");
        button_close.innerText = "Close";
        button_close.addEventListener("click", () => {
        modal.style.display = "none";
        });

        button_group.appendChild(button_submit);
        button_group.appendChild(button_close);

        modal_content.appendChild(header_text);
        modal_content.appendChild(summary);
        modal_content.appendChild(details);
        modal_content.appendChild(button_group);

        modal.appendChild(modal_content);
        modal.style.display = "block";

        window.addEventListener("click", (e) => {
        if (e.target === modal) {
            modal.style.display = "none";
        }
        });

        button_submit.addEventListener("click", function (event){
            create_new_todo_send_cb(socket_id);
        });

        const container = document.getElementById("container");
        container.appendChild(modal);
    }
}

function delete_todo_cb(socket_id, btn_id)
{

    let todo_deleted_cmd = {
        protocol:11,
        token:g_token,
        todo_id:btn_id,
    };

    console.log("Todo " + btn_id + " Delete Command Sended !!");

    socket_id.send(JSON.stringify(todo_deleted_cmd));
}

/*
function blockSleep(ms) {
  const end = Date.now() + ms;
  while (Date.now() < end) {}
}
*/

function create_main_page(socket_id, data_obj)
{
    const container = document.getElementById("container");
    container.innerHTML = "";
    container.style.cssText = "";

    const header_div = document.createElement("div");
    header_div.id = "header-div";
    const body_div = document.createElement("div");
    body_div.id = "body-div";

    header_div.style.backgroundColor = "#479cceff";
    header_div.style.padding = "10px";
    header_div.style.borderRadius = "3px";
    header_div.style.display = "flex";
    header_div.style.justifyContent = "space-between";

    const user_a = document.createElement("a");
    user_a.innerHTML = data_obj.name + " " + data_obj.last_name;
    user_a.style.color = "white";
    user_a.style.fontWeight = "bold";

    const new_todo = document.createElement("button");
    new_todo.innerText = "New Todo";
    new_todo.id = "new-todo-button";
    new_todo.style.marginRight = "10px";
    new_todo.addEventListener("click", function (event){
        create_new_todo_cb(socket_id);
    });

    header_div.appendChild(user_a);
    header_div.appendChild(new_todo);

    container.appendChild(header_div);
    container.appendChild(body_div);

    console.log("todo list req sended - token ", data_obj.token);

    g_token = data_obj.token;

    let get_todo_list_req = {
        protocol:10, //get todo list
        token:data_obj.token 
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
    body_div.style.backgroundColor = "#479cceff";
    body_div.style.padding = "10px";
    body_div.style.borderRadius = "3px";


    console.log("length:" + obj.todo_count);

    let todo_count = obj.todo_count;

    if(typeof todo_count === "number")
    {
        for(let i = 0; i < todo_count; i++)
        {
            const x_div = document.createElement("div");
            x_div.style.backgroundColor = "#dbebfcff"
            x_div.style.margin = "3px";
            x_div.style.padding = "5px";
            x_div.style.borderRadius = "3px";
            x_div.style.display = "flex";
            x_div.style.justifyContent = "space-between";

            const a_tag = document.createElement("a");
            a_tag.innerHTML = obj.todo_list[i].id + ") <" +
                                obj.todo_list[i].state + ">   " +
                                obj.todo_list[i].summary + ":  " +
                                obj.todo_list[i].details;
            x_div.appendChild(a_tag);

            const delete_btn = document.createElement("button");
            delete_btn.innerText = "Delete";
            delete_btn.id = "delete-button-" + obj.todo_list[i].id;
            delete_btn.addEventListener("click", function (event, id){
                delete_todo_cb(socket_id, obj.todo_list[i].id);
            });

            x_div.appendChild(delete_btn);

            body_div.appendChild(x_div);
        }
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

        if(obj.protocol == 4)
        {
            create_main_page(socket, obj); 
        }
        else if(obj.protocol == 10) // get todo list response
        {
            create_todo_list(socket, obj); 
        }
        else if((obj.protocol == 11) && (obj.error == 0)) // todo delete response
        {
            let get_todo_list_req = { protocol:10, token:g_token }; //get todo list
            socket.send(JSON.stringify(get_todo_list_req));
        }
        else if((obj.protocol == 12) && (obj.error == 0))// new todo list response
        {
            let get_todo_list_req = { protocol:10, token:g_token }; //get todo list
            socket.send(JSON.stringify(get_todo_list_req));
        }
        else
        {
            console.log("< Unknown Data Received > ");
        }
    };

    socket.onclose = () => {
        console.log("Connection Closed");
    };
}


// Create the websocket
create_websocket();






