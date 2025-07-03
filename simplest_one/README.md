# Demo

<video width="320" height="240" controls>
  <source src="out.mp4" type="video/mp4">
</video> 

# How to use it ?

Server side:

Just `gcc chat_server.c -o chat_server`

Client side:

Just `gcc chat_client.c -lncurses -lpthread -o chat_client`

Now start the server:

```
./chat_server
```

And the client:

```
./chat_client server_ip port username
```

**Happy chatting!!!**
