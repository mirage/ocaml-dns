%{
%}

%token EOF
%token EOL
%token SPACE
%token SNAMESERVER
%token DOT
%token COLON
%token PERCENT
%token <string> IPV4
%token <string> IPV6
%token <string> ZONE_ID

%start resolvconf
%type <[ `Nameserver of Ipaddr.t ] list> resolvconf

%%

resolvconf: lines EOF { List.rev $1 }

lines:
  /* nothing */ { [] }
 | lines EOL { $1 }
 | lines nameserver EOL { $2 :: $1 }

s: SPACE {} | s SPACE {}

ipv4: IPV4 { Ipaddr.V4.of_string_exn $1 }

ipv6:
 IPV6 { Ipaddr.V6.of_string_exn $1 }
 | IPV6 PERCENT ZONE_ID { Ipaddr.V6.of_string_exn $1 }

nameserver:
 SNAMESERVER s ipv4 { `Nameserver (Ipaddr.V4 $3) }
 | SNAMESERVER s ipv6 { `Nameserver (Ipaddr.V6 $3) }
