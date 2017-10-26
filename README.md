# jwt
    jwt

    Usage: jwt COMMAND [arg...]

    Stuff with jwt

    Commands:
      encode       encode
      refresh      refresh

    Run 'jwt COMMAND --help' for more information on a command
    
## Encode scopes into a token
    
    jwt encode --help

    Usage: jwt encode [OPTIONS]

    encode

    Options:
      -e, --scopes=[]      desc
      -k, --key=""         private key file
      -a, --subject="me"   subject
      
## Refresh existing token for 10 hours more
      
    jwt refresh --help

    Usage: jwt refresh [OPTIONS] TOKEN

    refresh

    Arguments:
      TOKEN=""     token that needs to be refreshed

    Options:
      -k, --key="~/.id_rsa"   private key file
