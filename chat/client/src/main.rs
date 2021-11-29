//client

use std::io::{self, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::mpsc::{self, TryRecvError};
use std::thread;
use std::time::Duration;
extern crate colored;
use colored::*;
extern crate magic_crypt;
use magic_crypt::MagicCryptTrait;
//use magic_crypt::new_magic_crypt;


// client

const LOCAL: &str = "127.0.0.1:6000";
const MSG_SIZE: usize = 128;

pub fn add(a: i32, b:i32) -> i32{
    a+b
}
pub fn is_server_online(ip: &str) -> bool{
    match TcpStream::connect(ip){
        Ok(_) => {return true},
        Err(_) => {return false}
    }
}

#[cfg(test)]
mod tests {
    use super ::*;

    #[test]
    fn test_add(){
        assert_eq!(add(1,2),3);
    }
    #[test]
    fn test_if_server_online(){
        assert_eq!(is_server_online(LOCAL), true);
    }
}
fn try_again(){
    println!("{}", "Appuyer sur :\n1 pour vous inscrire\n2 pour vous connecter".red().bold());
}
fn remove_trailing_zeros(data: &mut Vec<u8>) -> Vec<u8> {
    // Used to remove the zeros at the end of the received encrypted message
    // but not inside the message (purpose of the 'keep_push' var

    let mut transit:Vec<u8> = vec![];
    let mut res:Vec<u8> = vec![];
    let mut keep_push = false;
    for d in data.iter().rev() {
        if *d == 0 && !keep_push{
            continue;
        } else {
            transit.push(*d);
            keep_push = true;
        }
    }
    for t in transit.iter().rev() {
        res.push(*t);
    }
    return res.to_owned();
}

fn main() {
    if is_server_online(LOCAL){
        let mut client = TcpStream::connect(LOCAL).expect("Stream failed to connect");
        // let mut client_send = client.try_clone().expect("clone failed..");
        client.set_nonblocking(true).expect("failed to initiate non-blocking");
        let client_adrr = client.local_addr();
        let (tx, rx) = mpsc::channel::<String>();
        let mut authenticated = false;
        let mut conn = false;
        let mut count = 0;
        let mut _username = String::new();
        thread::spawn(move || loop {
            let mut buff = vec![0; MSG_SIZE];
            match client.read_exact(&mut buff) {
                Ok(_) => {
                    if authenticated && count > 1{
                        let msg = buff.into_iter().take_while(|&x| x != 0).collect::<Vec<_>>();
                        let msg = String::from_utf8(msg).expect("Invalid utf8 message");
                        let now = chrono::Utc::now();
                        let mc = magic_crypt::new_magic_crypt!("cledeouf", 256);
                        println!("[{}] - {:?}", now.format("%b %-d, %-I:%M").to_string().green().bold(), mc.decrypt_base64_to_string(msg).unwrap());
                    }else{
                        if count < 1{
                            buff = remove_trailing_zeros(&mut buff);
                            let mc = magic_crypt::new_magic_crypt!("cledeouf", 256);
                            let client_val = mc.decrypt_base64_to_string(std::str::from_utf8(&buff).unwrap());
                            match client_val{
                                Ok(_) => {
                                    if mc.decrypt_base64_to_string(std::str::from_utf8(&buff).unwrap()).unwrap() == "true" {
                                        println!("Verifying login!");
                                        conn = true;
                                        authenticated = true;
                                        count = 2;
                                        println!("{}", "Authenticated ! You may now chat below !".blue().bold());
                                    }else if mc.decrypt_base64_to_string(std::str::from_utf8(&buff).unwrap()).unwrap() == "false"{
                                        println!("Verifying login!");
                                        count = -1;
                                        conn = true;
                                        println!("still here");
                                    }
                                },
                                Err(_) => {}
                            }
                            
                            if !conn{
                                println!("Authenticating with server!");
                                buff = remove_trailing_zeros(&mut buff);
                                let mc = magic_crypt::new_magic_crypt!("cledeouf", 256);
                                println!("{:?}", mc.decrypt_base64_to_string(std::str::from_utf8(&buff).unwrap()).unwrap());             
                            }
                        }else{
                            if !conn{
                                let msg = buff.into_iter().take_while(|&x| x != 0).collect::<Vec<_>>();
                                let msg = String::from_utf8(msg).expect("Invalid utf8 message");
                                let mc = magic_crypt::new_magic_crypt!("cledeouf", 256);
                                _username = mc.decrypt_base64_to_string(msg).unwrap();
                                // println!("{:?}", _username);
                                authenticated = true;
                                println!("{}", "Authenticated ! You may now chat below !".blue().bold());
                            }

                        }
        
                        count = count + 1;
                    }
                },
                Err(ref err) if err.kind() == ErrorKind::WouldBlock => (),
                Err(_) => {
                    println!("la connection au server est coupée");
                    break;
                }
            }

            match rx.try_recv() {
                Ok(msg) => {
                    let mut buff = msg.clone().into_bytes();
                    buff.resize(MSG_SIZE, 0);
                    client.write_all(&buff).expect("writing to socket failed");
                }, 
                Err(TryRecvError::Empty) => (),
                Err(TryRecvError::Disconnected) => {}
            }
            
            thread::sleep(Duration::from_millis(100));
        });
        
        // Identification

        struct Identification{
            user: String,
            password: String,
            choice: String,
        }

        let mut input_choice = String::new();
        let mut input_user = String::new();
        let mut input_password = String::new();
        println!("

        _____ _           _     ____            
       / ____| |         | |   |  _ \\           
      | |    | |__   __ _| |_  | |_) | _____  __
      | |    | '_ \\ / _` | __| |  _ < / _ \\ \\/ /
      | |____| | | | (_| | |_  | |_) | (_) >  < 
       \\_____|_| |_|\\__,_|\\__| |____/ \\___/_/\\_\\
   
       ");

        loop{
            println!("{}", "\nBienvenue sur le Chat. Souhaitez-vous vous inscrire ou vous connecter ?\n\n1) S'inscrire\n\n2) Se connecter\n\n".blue().bold());
            match io::stdin().read_line(& mut input_choice){
                Ok(1) => {
                    if input_choice=="2\n"{
                        break;
                    }
                    if input_user.len() > 1{
                        // println!("{}", input_choice);
                        break;
                    }
                    try_again();
                    input_choice=String::new();
                }
                Ok(2) => {
                    // println!("{}", input_choice);
                    if input_choice=="1\n"{
                        break;
                    }
                    if input_choice=="2\n"{
                        break;
                    }
                    try_again();
                    input_choice=String::new();
                }
                Ok(_) => {
                    try_again();
                    input_choice=String::new();
                }
                Err(e) => println!("oups {}", e)
            }
        }
        loop{
            println!("\nVeuillez entrer votre nom d'utilisateur");
            match io::stdin().read_line(& mut input_user){
                Ok(_) => {
                    if input_user.len() > 1{
                        break;
                    }
                    input_user.clear();
                }
                Err(e) => println!("oups {}", e)
            }
        }

        loop{
            println!("\nVeuillez entrer votre mot de passe");
            match io::stdin().read_line(& mut input_password){
                Ok(_) => {
                    if input_password.len() > 1{
                        break;
                    }
                    input_password.clear();
                }
                Err(e) => println!("oups {}", e)
            }
        }
        let info = Identification {
            user: String::from(input_user),
            password: String::from(input_password),
            choice: String::from(input_choice),
        };

        let array: [String; 2] = [String::from(info.choice.to_string()+"\n\t\n"+&info.user.to_string()+"\n\t\n"+&info.password.to_string()),String::from(":quit")];
            
        loop {
            let mut buff2;
            for x in array {
                buff2 = x.to_string();
                let msg = buff2.trim().to_string();
                if msg == ":quit" || tx.send(msg).is_err() {break}
            }
            break;
        }

        //
        // Lancement du programme si retour ok du serveur
        let connection = sqlite::open("../server/rust.db").unwrap();


        loop {
            let mut buff = String::new();
            io::stdin().read_line(&mut buff).expect("reading from stdin failed");
            let msg = buff.trim().to_string();
            let mut msg2 = msg.clone();
            let mut usernamefinal = String::new();
            // println!("{:?}", client_adrr);
            let mut sqlcommande = String::from("SELECT client_id FROM EN_LIGNE where ip_port = '");
            sqlcommande.push_str(&client_adrr.as_ref().unwrap().to_string());
            sqlcommande.push_str("';");
            // println!("{}", sqlcommande);
            connection
            .iterate(sqlcommande, |pairs| {
                for &(_column, value) in pairs.iter() {
                    // println!("Ton username : {}", value.unwrap());
                    usernamefinal = value.unwrap().to_string();
                }
                true
            })
            .unwrap();    
            // println!("{:?}", _username);
            msg2 = usernamefinal + &" : " + &msg2;
            let mc = magic_crypt::new_magic_crypt!("cledeouf", 256);
            let base64_msg = mc.encrypt_str_to_base64(msg2);

            //println!("{}", msg);
            if msg == ":quit" || tx.send(base64_msg).is_err() {break}
        }
        println!("bye bye!");
    }else{
        println!("{}", "\n\tLe serveur n'est pas allumé!\n".red().bold());
    }
}

