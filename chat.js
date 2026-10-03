(() => {
  "use strict";
  const API_BASE = "https://omwei-private-chat.slevarsky.workers.dev";
  const $ = (id) => document.getElementById(id);
  const state = {roomId:null, chatDeleted:false, token:null, ws:null, keyPair:null, peerPublicKey:null, cryptoKey:null, pending:new Map()};
  const enc = new TextEncoder(), dec = new TextDecoder();

  function b64u(bytes){let s="";for(const b of bytes)s+=String.fromCharCode(b);return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");}
  function fromB64u(s){s=s.replace(/-/g,"+").replace(/_/g,"/");while(s.length%4)s+="=";const bin=atob(s);return Uint8Array.from(bin,c=>c.charCodeAt(0));}
  function randomId(bytes=16){return b64u(crypto.getRandomValues(new Uint8Array(bytes)));}
  async function deriveKey(peerJwk){
    const peer=await crypto.subtle.importKey("jwk",peerJwk,{name:"ECDH",namedCurve:"P-256"},false,[]);
    const bits=await crypto.subtle.deriveBits({name:"ECDH",public:peer},state.keyPair.privateKey,256);
    return crypto.subtle.deriveKey({name:"HKDF",hash:"SHA-256",salt:enc.encode(state.roomId),info:enc.encode("OMWEI-private-chat-v1")},await crypto.subtle.importKey("raw",bits,"HKDF",false,["deriveKey"]),{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
  }
  async function encrypt(plaintext){if(!state.cryptoKey)throw new Error("The other participant is not connected yet.");const iv=crypto.getRandomValues(new Uint8Array(12));const ciphertext=await crypto.subtle.encrypt({name:"AES-GCM",iv},state.cryptoKey,enc.encode(plaintext));return {iv:b64u(iv),data:b64u(new Uint8Array(ciphertext))};}
  async function decrypt(payload){const plaintext=await crypto.subtle.decrypt({name:"AES-GCM",iv:fromB64u(payload.iv)},state.cryptoKey,fromB64u(payload.data));return dec.decode(plaintext);}
  async function makeKeys(){state.keyPair=await crypto.subtle.generateKey({name:"ECDH",namedCurve:"P-256"},true,["deriveBits"]);return crypto.subtle.exportKey("jwk",state.keyPair.publicKey);}
  function setStatus(id,text){$(id).textContent=text;} function show(id){$(id).classList.remove("hidden");} function hide(id){$(id).classList.add("hidden");}

  async function endChat(){
    if(!state.roomId||!state.token)return;
    try{
      const res=await fetch(API_BASE+"/room/end",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({roomId:state.roomId,token:state.token})});
      if(!res.ok)throw new Error("Could not end chat.");
      if(state.ws)state.ws.close(4002,"chat ended");
      sessionStorage.removeItem("omwei-chat-session");
      state.roomId=null;state.token=null;state.ws=null;
      $("messages").replaceChildren();
      hide("chat");show("welcome");
      setStatus("status","Chat ended. You can create a new private chat.");
    }catch(_){setStatus("chatStatus","Could not end chat.");}
  }

  async function deleteChat(){
    if(!state.roomId||!state.token)return;
    try{
      await fetch(API_BASE+"/room/clear",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({roomId:state.roomId,token:state.token})});
      $("messages").replaceChildren();
      setStatus("peerStatus","Chat cleared. Encrypted connection remains ready.");
    }catch(_){setStatus("chatStatus","Could not clear chat.");}
  }

  async function createRoom(){
    setStatus("status","Creating private room…");
    const res=await fetch(API_BASE+"/room",{method:"POST",headers:{"content-type":"application/json"}});
    if(!res.ok)throw new Error("Could not create room.");
    const data=await res.json();state.roomId=data.roomId;state.token=data.token;
    const invite=location.origin+location.pathname+"#room="+encodeURIComponent(state.roomId)+"&invite="+encodeURIComponent(data.inviteToken);
    $("inviteLink").value=invite;hide("welcome");show("invite");
    sessionStorage.setItem("omwei-chat-session",JSON.stringify({roomId:state.roomId,token:state.token}));
    setStatus("inviteStatus","Invite created. The link is one-time and should be shared privately.");
  }

  async function joinFromInvite(roomId,inviteToken){
    const res=await fetch(API_BASE+"/room/join",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({roomId,inviteToken})});
    if(!res.ok)throw new Error("Invite is invalid or already used.");
    const data=await res.json();state.roomId=roomId;state.token=data.token;
    sessionStorage.setItem("omwei-chat-session",JSON.stringify({roomId,token:state.token}));
    history.replaceState(null,"",location.pathname);await startChat();
  }

  async function startChat(){
    hide("welcome");hide("invite");show("chat");
    const publicJwk=await makeKeys();
    const url=API_BASE.replace(/^http/,"ws")+"/room/"+encodeURIComponent(state.roomId)+"?token="+encodeURIComponent(state.token);
    state.ws=new WebSocket(url);
    state.ws.onopen=()=>{setStatus("peerStatus","Connected. Waiting for the other participant…");state.ws.send(JSON.stringify({type:"key",key:publicJwk}));};
    state.ws.onmessage=async(event)=>{
      try{
        const msg=JSON.parse(event.data);console.log("[chat] WS <-",msg.type,msg);
        if(msg.type==="peer-key"){state.peerPublicKey=msg.key;state.cryptoKey=await deriveKey(msg.key);setStatus("peerStatus","Encrypted connection ready.");}
        else if(msg.type==="message"){const text=await decrypt(msg.payload);console.log("[chat] displaying message",msg.id);addMessage(msg.id,text,false);}
        else if(msg.type==="deleted"){console.log("[chat] deleted",msg.id);const el=document.querySelector('[data-message-id="'+CSS.escape(msg.id)+'"]');if(el)el.remove();}
        else if(msg.type==="chat-cleared"){$("messages").replaceChildren();setStatus("peerStatus","Chat cleared. Encrypted connection remains ready.");}
        else if(msg.type==="chat-ended"){
          if(state.ws)state.ws.close(4002,"chat ended");
          sessionStorage.removeItem("omwei-chat-session");
          state.roomId=null;
          state.token=null;
          state.ws=null;
          $("messages").replaceChildren();
          hide("chat");
          show("welcome");
          setStatus("status","Chat ended. You can create a new private chat.");
        }
        else if(msg.type==="peer-left"){if(!state.chatDeleted)setStatus("peerStatus","The other participant has left.");}
        else if(msg.type==="error"){setStatus("chatStatus",msg.message||"Chat error.");}
      }catch(e){setStatus("chatStatus","Unable to process a message.");}
    };
    state.ws.onclose=()=>{if(state.chatDeleted)setStatus("peerStatus","Chat deleted.");else setStatus("peerStatus","Disconnected. Click Leave room to return.");};
    state.ws.onerror=()=>setStatus("peerStatus","Connection error.");
  }

  function setChatDeletedUI(){$("messageInput").disabled=true;$("messageInput").placeholder="Chat deleted.";$("sendForm").querySelector('button[type="submit"]').disabled=true;} function addMessage(id,text,mine){const el=document.createElement("div");el.className="message "+(mine?"mine":"theirs");el.dataset.messageId=id;el.textContent=text;$("messages").appendChild(el);$("messages").scrollTop=$("messages").scrollHeight;}

  $("createBtn").addEventListener("click",()=>createRoom().catch(e=>setStatus("status",e.message)));
  $("copyBtn").addEventListener("click",async()=>{await navigator.clipboard.writeText($("inviteLink").value);setStatus("inviteStatus","Invite copied.");});
  $("openBtn").addEventListener("click",()=>startChat().catch(e=>setStatus("inviteStatus",e.message)));
  $("deleteBtn").addEventListener("click",()=>{if(confirm("Clear this chat for both participants? Current messages will be removed."))deleteChat();});
  $("endBtn").addEventListener("click",()=>{if(confirm("End this private chat for both participants? The room will be closed and a new chat can be created."))endChat();});
  $("leaveBtn").addEventListener("click",()=>{if(state.ws)state.ws.close(1000,"left");sessionStorage.removeItem("omwei-chat-session");location.href=location.pathname;});
  $("sendForm").addEventListener("submit",async(e)=>{e.preventDefault();const input=$("messageInput"),text=input.value.trim();if(!text||!state.ws||state.ws.readyState!==WebSocket.OPEN)return;try{const payload=await encrypt(text),id=randomId(18);state.ws.send(JSON.stringify({type:"send",id,payload}));addMessage(id,text,true);input.value="";}catch(err){setStatus("chatStatus",err.message);}});

  (async()=>{const hash=new URLSearchParams(location.hash.slice(1)),room=hash.get("room"),invite=hash.get("invite");if(room&&invite){try{await joinFromInvite(room,invite);}catch(e){setStatus("status",e.message);}return;}const saved=sessionStorage.getItem("omwei-chat-session");if(saved){try{const s=JSON.parse(saved);state.roomId=s.roomId;state.token=s.token;await startChat();}catch(_){}}})();
})();