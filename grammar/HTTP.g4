// ANTLR4 HTTP Request Grammar for Stratagem
grammar HTTP;

httpMessage
    : requestLine (headerLine)* CRLF messageBody? EOF
    ;

requestLine
    : method SP requestTarget SP httpVersion CRLF
    ;

method
    : 'GET' | 'POST' | 'PUT' | 'DELETE' | 'HEAD' | 'OPTIONS' | 'PATCH' | 'CONNECT' | 'TRACE' | TOKEN
    ;

requestTarget
    : originForm
    | absoluteForm
    | authorityForm
    | asteriskForm
    ;

originForm
    : '/' (VCHAR)*
    ;

absoluteForm
    : 'http' 's'? '://' VCHAR*
    ;

authorityForm
    : VCHAR+ ':' DIGIT+
    ;

asteriskForm
    : '*'
    ;

httpVersion
    : 'HTTP/' DIGIT '.' DIGIT
    ;

headerLine
    : headerName ':' OWS headerValue OWS CRLF
    ;

headerName
    : TOKEN
    ;

headerValue
    : (VCHAR | SP | HTAB)*
    ;

messageBody
    : .*?
    ;

TOKEN
    : [a-zA-Z0-9!#$%&'*+-.^_`|~]+
    ;

CRLF
    : '\r\n'
    ;

SP
    : ' '
    ;

HTAB
    : '\t'
    ;

OWS
    : [ \t]*
    ;

DIGIT
    : [0-9]
    ;

VCHAR
    : [\u0021-\u007E]
    ;
