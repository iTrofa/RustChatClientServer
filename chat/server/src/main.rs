//server
use std::io::{ErrorKind, Read, Write};
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::mpsc;
use std::thread;
extern crate sqlite;
extern crate magic_crypt;
extern crate colored;
extern crate rand;

use magic_crypt::MagicCryptTrait;
use colored::*;
use rand::Rng; // 0.8.0

const LOCAL: &str = "127.0.0.1:6000";
const MSG_SIZE: usize = 128;

// server
fn send_message_to_client(client: &mut TcpStream, msg: &[u8]) {
    // Used to send to a specific client
    let mut buff = msg.to_vec();
    buff.resize(MSG_SIZE, 0);
    client.write_all(&buff).map(|_| client).ok();
    // println!("I'm out");
}

fn sleep() {
    thread::sleep(::std::time::Duration::from_millis(100));
}

fn main() {

    let server = TcpListener::bind(LOCAL).expect("Listener failed to bind");
    server.set_nonblocking(true).expect("failed to initialize non-blocking");
    let mut premiereconnection = true;
    let mut clients = vec![];
    let (tx, rx) = mpsc::channel::<String>();
    let mut number = 1;
    let connection = sqlite::open("rust.db").unwrap();
    connection
    .execute(
        "
        DROP TABLE IF EXISTS EN_LIGNE;
        CREATE TABLE IF NOT EXISTS EN_LIGNE (client_id TEXT, ip_port TEXT, username TEXT, passwd TEXT);
        ",
    )
    .unwrap();
    
    loop {

        if let Ok((mut socket, addr)) = server.accept() {
            println!("Client {} connected", addr);
            // println!("{}", number);  
            // creation de la commande pour insertion des nouvelles connections dans la base de donnée EN_LIGNE
            let addresse_ip = &addr.to_string();
            // println!("{}", addresse_ip);
            let mut sqlcommande = String::from("INSERT INTO EN_LIGNE VALUES (");
            sqlcommande.push_str("'Client ");
            sqlcommande.push_str(&number.to_string());
            sqlcommande.push_str("','");
            sqlcommande.push_str(&addresse_ip.to_string());
            sqlcommande.push_str("','");
            sqlcommande.push_str("','");
            sqlcommande.push_str("');");

            // println!("{}", sqlcommande);
            number+=1;
            
            connection
                .execute(
                    sqlcommande
                    ,
                )
                .unwrap();

            connection
            .iterate("SELECT COUNT(*) FROM EN_LIGNE", |pairs| {
                for &(_column, value) in pairs.iter() {
                    println!("Il y a actuellement {} utilisateur(s) en ligne", value.unwrap());
                }
                true
            })
            .unwrap();            
                        
            let tx = tx.clone();
            clients.push(socket.try_clone().expect("failed to clone client"));
            thread::spawn(move || loop {
                let mut buff = vec![0; MSG_SIZE];
                match socket.read_exact(&mut buff) {
                    Ok(_) => {
                        let msg = buff.into_iter().take_while(|&x| x != 0).collect::<Vec<_>>();
                        // Checker en base de données et integrer les informations
                        if premiereconnection==true{
                            let mut vecteurmsg = Vec::new();
                            let mut tableau_info = Vec::new();
                            let msg2 = msg.clone();
                            for x in msg2{
                                let min:u8 = 10;
                                let mun:u8 = 9;
                                if x!=min && x!=mun{
                                    vecteurmsg.push(x)
                                }else{
                                    tableau_info.push(vecteurmsg);
                                    vecteurmsg = Vec::new();
                                }
                            }
                            tableau_info.push(vecteurmsg);
                            let user = &tableau_info[4];
                            let user = String::from_utf8(user.to_vec());
                            let choice = &tableau_info[0];
                            let choice = String::from_utf8(choice.to_vec());
                            let passwd = &tableau_info[8];
                            let passwd = String::from_utf8(passwd.to_vec());
                            println!("User : {} - Password : {} - Mode : {}",user.as_ref().unwrap(), passwd.as_ref().unwrap(), choice.as_ref().unwrap());
                            let connection = sqlite::open("rust.db").unwrap();
                            if choice.as_ref().unwrap() == &"1".to_string(){
                                // Generate random number in the range [0, 99]
                                let mut randnum = String::new(); 
                                for _ in 1..5 {
                                    let num = rand::thread_rng().gen_range(0..10);
                                    randnum = randnum.to_string() + &num.to_string();
                                }   
                                //BDD
                                // on ajoute le pseudo avec l'id unique.

                                let mut sqlcommande = String::from("UPDATE EN_LIGNE SET client_id = '");
                                sqlcommande.push_str(&user.as_ref().unwrap().to_string());
                                sqlcommande.push_str("#");
                                sqlcommande.push_str(&randnum.to_string());
                                sqlcommande.push_str("' WHERE ip_port = '");
                                sqlcommande.push_str(&addr.to_string());
                                sqlcommande.push_str("';");
                                connection.execute(sqlcommande,).unwrap();   

                                // on ajoute le pseudo utilisé pour login 

                                let mut sqlcommande = String::from("UPDATE EN_LIGNE SET username = '");
                                sqlcommande.push_str(user.as_ref().unwrap());
                                sqlcommande.push_str("' WHERE ip_port = '");
                                sqlcommande.push_str(&addr.to_string());
                                sqlcommande.push_str("';");
                                connection.execute(sqlcommande,).unwrap(); 

                                // on ajoute le mdp du client

                                let mut sqlcommande = String::from("UPDATE EN_LIGNE SET passwd = '");
                                sqlcommande.push_str(passwd.as_ref().unwrap());
                                sqlcommande.push_str("' WHERE ip_port = '");
                                sqlcommande.push_str(&addr.to_string());
                                sqlcommande.push_str("';");
                                connection.execute(sqlcommande,).unwrap(); 
                                    let userrand = user.as_ref().unwrap().to_owned() + &"#" + &randnum;
                                    let message_bienvenue = "Bienvenue sur le chat!";
                                    let mc = magic_crypt::new_magic_crypt!("cledeouf", 256);
                                    let base64_msg = mc.encrypt_str_to_base64(message_bienvenue);
                                    let client_username = mc.encrypt_str_to_base64(userrand);
                                    // on renvoie l'user au client pour utiliser dans le chat.
                                    send_message_to_client(& mut socket, base64_msg.as_bytes());
                                    send_message_to_client(& mut socket, client_username.as_bytes());
                            }else{
                                // println!("CONNECTION");
                                let mut sqlcommande = String::from("SELECT count(*) FROM EN_LIGNE WHERE username = '");
                                sqlcommande.push_str(user.as_ref().unwrap());
                                sqlcommande.push_str("' and passwd = '");
                                sqlcommande.push_str(passwd.as_ref().unwrap());
                                sqlcommande.push_str("';");
                                // println!("{}", sqlcommande);
                                let mut validate = "false";
                                connection.iterate(sqlcommande, |pairs| {
                                    for &(_column, value) in pairs.iter() {
                                        if value.unwrap() == "1"{
                                            validate = "true";
                                        }
                                    }
                                    true
                                }).unwrap();
                                let mc = magic_crypt::new_magic_crypt!("cledeouf", 256);
                                let client_validate = mc.encrypt_str_to_base64(validate);
                                send_message_to_client(& mut socket, client_validate.as_bytes());

                                if validate == "true"{
                                    // we recover the client_id from the other connection
                                    let mut sqlcommande = String::from("SELECT client_id FROM EN_LIGNE WHERE username = '");
                                    sqlcommande.push_str(user.as_ref().unwrap());
                                    sqlcommande.push_str("' and passwd = '");
                                    sqlcommande.push_str(passwd.as_ref().unwrap());
                                    sqlcommande.push_str("';");
                                    let mut conn_client_id = String::new();
                                    connection.iterate(sqlcommande, |pairs| {
                                        for &(_column, value) in pairs.iter() {
                                            if value.unwrap().len() > 1{ 
                                                conn_client_id = value.unwrap().to_string();
                                            }
                                        }
                                        true
                                    }).unwrap();
                                    // add client_id to new connection 
                                    let mut sqlcommande = String::from("UPDATE EN_LIGNE SET client_id = '");
                                    sqlcommande.push_str(&conn_client_id);
                                    sqlcommande.push_str("' WHERE ip_port = '");
                                    sqlcommande.push_str(&addr.to_string());
                                    sqlcommande.push_str("';");
                                    connection.execute(sqlcommande,).unwrap();
                                }
                             
                            }
                        }
                        
                        if premiereconnection==false{
                            let msg = String::from_utf8(msg).expect("Invalid utf8 message");
                            // ici ajouter le user de la bdd via jointure en ligne -- user
                            tx.send(msg).expect("failed to send msg to rx");
                            
                            
                        }
                        premiereconnection=false;
                    }, 
                    Err(ref err) if err.kind() == ErrorKind::WouldBlock => (),
                    Err(_) => {
                        println!("closing connection with: {}", addr);
                        // Supprimer ici les mecs de la bdd EN_LIGNE
                        let mut sqlcommande = String::from("DELETE FROM EN_LIGNE WHERE ip_port = '");
                        sqlcommande.push_str(&addr.to_string());
                        sqlcommande.push_str("';");
                        // println!("{}", sqlcommande);
                        let connection = sqlite::open("rust.db").unwrap();
                        connection
                        .execute(
                            sqlcommande
                            ,
                        )
                        .unwrap();
                        connection
                        .iterate("SELECT COUNT(*) FROM EN_LIGNE", |pairs| {
                            for &(_column, value) in pairs.iter() {
                                println!("Il y a actuellement {} utilisateur(s) en ligne", value.unwrap());
                            }
                            true
                        })
                        .unwrap();   
                        break;
                    }
                }

                sleep();
            });
        }

        if let Ok(msg) = rx.try_recv() {
            clients = clients.into_iter().filter_map(|mut client| {
                let mut buff = msg.clone().into_bytes();
                buff.resize(MSG_SIZE, 0);
                client.write_all(&buff).map(|_| client).ok()
            }).collect::<Vec<_>>();
        let mc = magic_crypt::new_magic_crypt!("cledeouf", 256);
        let now = chrono::Utc::now();
        println!("[{}] - {:?}", now.format("%b %-d, %-I:%M").to_string().green().bold(), mc.decrypt_base64_to_string(&msg).unwrap());
        }
        sleep();
    }
}
