// ANTLR4 SMTP Command Grammar for Stratagem
grammar SMTP;

smtpSession
    : (command CRLF)* EOF
    ;

command
    : heloCmd
    | ehloCmd
    | mailCmd
    | rcptCmd
    | dataCmd
    | rsetCmd
    | noopCmd
    | quitCmd
    | vrfyCmd
    ;

heloCmd
    : 'HELO' SP domain
    ;

ehloCmd
    : 'EHLO' SP (domain | addressLiteral)
    ;

mailCmd
    : 'MAIL FROM:' reversePath (SP mailParams)?
    ;

rcptCmd
    : 'RCPT TO:' forwardPath (SP rcptParams)?
    ;

dataCmd
    : 'DATA'
    ;

rsetCmd
    : 'RSET'
    ;

noopCmd
    : 'NOOP' (SP string)?
    ;

quitCmd
    : 'QUIT'
    ;

vrfyCmd
    : 'VRFY' SP string
    ;

reversePath
    : '<' path? '>'
    ;

forwardPath
    : '<' path '>'
    ;

path
    : (atDomainList ':')? localPart '@' domain
    ;

atDomainList
    : '@' domain (',' '@' domain)*
    ;

domain
    : [a-zA-Z0-9.-]+
    ;

addressLiteral
    : '[' [a-zA-Z0-9.:]+ ']'
    ;

localPart
    : [a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+
    ;

mailParams
    : [a-zA-Z0-9= _-]+
    ;

rcptParams
    : [a-zA-Z0-9= _-]+
    ;

string
    : [a-zA-Z0-9._-]+
    ;

SP
    : ' '
    ;

CRLF
    : '\r\n'
    ;
