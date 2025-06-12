ARG VERSION=3.8
#immagine di partenza
FROM alpine:$VERSION

LABEL maintainer="fabio@moku.io"

# dichiarazione variabile per poterla usare anche durante la build,
# altrimenti non sarebbe stato possibile utilizzare la variabile dopo
# l'esecuzione del comando FROM
ARG VERSION

# modalità bash
RUN echo $VERSION

# modalità exec
RUN ["echo", "$VERSION" ]

# comando eseguito all'avvio di un container a partire da questa immagine
CMD [ "/bin/sh"]