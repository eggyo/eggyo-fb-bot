/*
 * Copyright 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

/* jshint node: true, devel: true */
'use strict';

const
  bodyParser = require('body-parser'),
  config = require('config'),
  crypto = require('crypto'),
  express = require('express'),
  https = require('https'),
  request = require('request');

var app = express();

app.set('port', process.env.PORT || 5000);
app.use(bodyParser.json({
  verify: verifyRequestSignature
}));
app.use(express.static('public'));

/*
 * Be sure to setup your config values before running this code. You can
 * set them using environment variables or modifying the config file in /config.
 *
 */

// App Secret can be retrieved from the App Dashboard
const APP_SECRET = (process.env.MESSENGER_APP_SECRET) ?
  process.env.MESSENGER_APP_SECRET :
  config.get('appSecret');

// Arbitrary value used to validate a webhook
const VALIDATION_TOKEN = (process.env.MESSENGER_VALIDATION_TOKEN) ?
  (process.env.MESSENGER_VALIDATION_TOKEN) :
  config.get('validationToken');

// Generate a page access token for your page from the App Dashboard
const PAGE_ACCESS_TOKEN = (process.env.MESSENGER_PAGE_ACCESS_TOKEN) ?
  (process.env.MESSENGER_PAGE_ACCESS_TOKEN) :
  config.get('pageAccessToken');

if (!(APP_SECRET && VALIDATION_TOKEN && PAGE_ACCESS_TOKEN)) {
  console.error("Missing config values");
  process.exit(1);
}

/*
 * Use your own validation token. Check that the token used in the Webhook
 * setup is the same token used here.
 *
 */
app.get('/webhook', function(req, res) {
  if (req.query['hub.mode'] === 'subscribe' &&
    req.query['hub.verify_token'] === VALIDATION_TOKEN) {
    console.log("Validating webhook");
    res.status(200).send(req.query['hub.challenge']);
  } else {
    console.error("Failed validation. Make sure the validation tokens match.");
    res.sendStatus(403);
  }
});


/*
 * All callbacks for Messenger are POST-ed. They will be sent to the same
 * webhook. Be sure to subscribe your app to your page to receive callbacks
 * for your page.
 * https://developers.facebook.com/docs/messenger-platform/product-overview/setup#subscribe_app
 *
 */
app.post('/webhook', function(req, res) {
  var data = req.body;

  // Make sure this is a page subscription
  if (data.object == 'page') {
    // Iterate over each entry
    // There may be multiple if batched
    console.log("data: ", JSON.stringify(data));

    data.entry.forEach(function(pageEntry) {
      var pageID = pageEntry.id;
      var timeOfEvent = pageEntry.time;

      // Iterate over each messaging event
      if (pageEntry.messaging) {
        pageEntry.messaging.forEach(function(messagingEvent) {
          if (messagingEvent.optin) {
            receivedAuthentication(messagingEvent);
          } else if (messagingEvent.message) {
            receivedMessage(messagingEvent);
          } else if (messagingEvent.delivery) {
            receivedDeliveryConfirmation(messagingEvent);
          } else if (messagingEvent.postback) {
            receivedPostback(messagingEvent);
          } else if (messagingEvent.read) {
            receivedMessageRead(messagingEvent);
          } else {
            console.log("Webhook received unknown messagingEvent: ", messagingEvent);
          }
        });
      }

      if (pageEntry.changes) {
        console.log("changes: ", JSON.stringify(pageEntry.changes));

        pageEntry.changes.forEach(function(changesEvent) {
          if (changesEvent.value.item == "comment" && changesEvent.value.message) {
            console.log(changesEvent.value.sender_name + "--> comment : " + changesEvent.value.message);
            //callPrivateReplyAPI(changesEvent.value.comment_id, "ที่คุณลูกค้าสอบถาม รายละเอียดตามนี้เลยค่ะ ............");
            //callCommentsReplyAPI(changesEvent.value.comment_id, "Admin ทักไปทาง Inbox แล้วค่ะ");
          }
        });
      }

    });

    // Assume all went well.
    //
    // You must send back a 200, within 20 seconds, to let us know you've
    // successfully received the callback. Otherwise, the request will time out.
    res.sendStatus(200);
  }
});

/*
 * Verify that the callback came from Facebook. Using the App Secret from
 * the App Dashboard, we can verify the signature that is sent with each
 * callback in the x-hub-signature field, located in the header.
 *
 * https://developers.facebook.com/docs/graph-api/webhooks#setup
 *
 */
function verifyRequestSignature(req, res, buf) {
  var signature = req.headers["x-hub-signature"];

  if (!signature) {
    // For testing, let's log an error. In production, you should throw an
    // error.
    console.error("Couldn't validate the signature.");
  } else {
    var elements = signature.split('=');
    var method = elements[0];
    var signatureHash = elements[1];

    var expectedHash = crypto.createHmac('sha1', APP_SECRET)
      .update(buf)
      .digest('hex');

    if (signatureHash != expectedHash) {
      throw new Error("Couldn't validate the request signature.");
    }
  }
}

/*
 * Authorization Event
 *
 * The value for 'optin.ref' is defined in the entry point. For the "Send to
 * Messenger" plugin, it is the 'data-ref' field. Read more at
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/authentication
 *
 */
function receivedAuthentication(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfAuth = event.timestamp;

  // The 'ref' field is set in the 'Send to Messenger' plugin, in the 'data-ref'
  // The developer can set this to an arbitrary value to associate the
  // authentication callback with the 'Send to Messenger' click event. This is
  // a way to do account linking when the user clicks the 'Send to Messenger'
  // plugin.
  var passThroughParam = event.optin.ref;

  console.log("Received authentication for user %d and page %d with pass " +
    "through param '%s' at %d", senderID, recipientID, passThroughParam,
    timeOfAuth);

  // When an authentication is received, we'll send a message back to the sender
  // to let them know it was successful.
  sendTextMessage(senderID, "Authentication successful");
}


/*
 * Message Event
 *
 * This event is called when a message is sent to your page. The 'message'
 * object format can vary depending on the kind of message that was received.
 * Read more at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-received
 *
 * For this example, we're going to echo any text that we get. If we get some
 * special keywords ('button', 'generic', 'receipt'), then we'll send back
 * examples of those bubbles to illustrate the special message bubbles we've
 * created. If we receive a message with an attachment (image, video, audio),
 * then we'll simply confirm that we've received the attachment.
 *
 */
function receivedMessage(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfMessage = event.timestamp;
  var message = event.message;

  console.log("Received message for user %d and page %d at %d with message:",
    senderID, recipientID, timeOfMessage);
  console.log(JSON.stringify(message));

  var isEcho = message.is_echo;
  var messageId = message.mid;
  var appId = message.app_id;
  var metadata = message.metadata;

  // You may get a text or attachment but not both
  var messageText = message.text;
  var messageAttachments = message.attachments;
  var quickReply = message.quick_reply;

  if (isEcho) {
    // Just logging message echoes to console
    console.log("Received echo for message %s and app %d with metadata %s",
      messageId, appId, metadata);
    return;
  } else if (quickReply) {
    var quickReplyPayload = quickReply.payload;

    console.log("Quick reply for message %s with payload %s and quickReply %s",
      messageId, quickReplyPayload, quickReply);

    sendTextMessage(senderID, "You choose answer : " + quickReplyPayload);
    if (messageText == quickReplyPayload) {
      sendTextMessage(senderID, "You choose correct answer");
    } else {
      sendTextMessage(senderID, "You choose wrong answer");
    }
    return;
  }

  if (messageText) {

    // If we receive a text message, check to see if it matches any special
    // keywords and send back the corresponding example. Otherwise, just echo
    // the text we received.
    switch (messageText) {
      case 'image':
        sendImageMessage(senderID);
        break;

      case 'gif':
        sendGifMessage(senderID);
        break;

      case 'audio':
        sendAudioMessage(senderID);
        break;

      case 'video':
        sendVideoMessage(senderID);
        break;

      case 'file':
        sendFileMessage(senderID);
        break;

      case 'button':
        sendButtonMessage(senderID);
        break;

      case 'generic':
        sendGenericMessage(senderID);
        break;

      case 'receipt':
        sendReceiptMessage(senderID);
        break;

      case 'quick reply':
        sendQuickReply(senderID);
        break

      case 'read receipt':
        sendReadReceipt(senderID);
        break

      case 'typing on':
        sendTypingOn(senderID);
        break

      case 'typing off':
        sendTypingOff(senderID);
        break

      case 'test':
        callParseServerCloudCode("testMsg", '{"msg":"fuck"}', function(response) {
          sendTextMessage(senderID, response);
        });
        break

      case '#help':
        sendHelpTips(senderID);
        break

      case '#menu':
        sendMenu(senderID);
        break

      case '#quiz':
        sendQuiz(senderID, "test quiz message", 2);
        break

      default:
        processMessage(messageText, function(responseMsg) {
          if (responseMsg == messageText) {
            callParseServerCloudCode("getReplyMsg", '{"msg":"' + messageText + '"}', function(response) {
              if (response == "") {
                console.log("no msg reply");
                sendTextMessage(senderID, "ข้าไม่เข้าใจที่เจ้าพูด");
              } else {
                sendTextMessage(senderID, response);
              }
            });
          } else {
            sendTextMessage(senderID, responseMsg);
          }
        });

    }
  } else if (messageAttachments) {
    sendTextMessage(senderID, "Message with attachment received");
  }
}


/*
 * Delivery Confirmation Event
 *
 * This event is sent to confirm the delivery of a message. Read more about
 * these fields at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-delivered
 *
 */
function receivedDeliveryConfirmation(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var delivery = event.delivery;
  var messageIDs = delivery.mids;
  var watermark = delivery.watermark;
  var sequenceNumber = delivery.seq;

  if (messageIDs) {
    messageIDs.forEach(function(messageID) {
      console.log("Received delivery confirmation for message ID: %s",
        messageID);
    });
  }

  console.log("All message before %d were delivered.", watermark);
}


/*
 * Postback Event
 *
 * This event is called when a postback is tapped on a Structured Message.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/postback-received
 *
 */
function receivedPostback(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfPostback = event.timestamp;

  // The 'payload' param is a developer-defined field which is set in a postback
  // button for Structured Messages.
  var payload = event.postback.payload;

  console.log("Received postback for user %d and page %d with payload '%s' " +
    "at %d", senderID, recipientID, payload, timeOfPostback);

  // When a postback is called, we'll send a message back to the sender to
  // let them know it was successful
  sendTextMessage(senderID, "Postback called");
}

/*
 * Message Read Event
 *
 * This event is called when a previously-sent message has been read.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-read
 *
 */
function receivedMessageRead(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;

  // All messages before watermark (a timestamp) or sequence have been seen.
  var watermark = event.read.watermark;
  var sequenceNumber = event.read.seq;

  console.log("Received message read event for watermark %d and sequence " +
    "number %d", watermark, sequenceNumber);
}

/*
 * Send an image using the Send API.
 *
 */
function sendImageMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "image",
        payload: {
          url: "http://messengerdemo.parseapp.com/img/rift.png"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a Gif using the Send API.
 *
 */
function sendGifMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "image",
        payload: {
          url: "http://messengerdemo.parseapp.com/img/instagram_logo.gif"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send audio using the Send API.
 *
 */
function sendAudioMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "audio",
        payload: {
          url: "http://messengerdemo.parseapp.com/audio/sample.mp3"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a video using the Send API.
 *
 */
function sendVideoMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "video",
        payload: {
          url: "http://messengerdemo.parseapp.com/video/allofus480.mov"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a video using the Send API.
 *
 */
function sendFileMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "file",
        payload: {
          url: "http://messengerdemo.parseapp.com/files/test.txt"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a text message using the Send API.
 *
 */
function sendTextMessage(recipientId, messageText) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: messageText,
      metadata: "DEVELOPER_DEFINED_METADATA"
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a button message using the Send API.
 *
 */
function sendButtonMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "This is test text",
          buttons: [{
            type: "web_url",
            url: "https://www.oculus.com/en-us/rift/",
            title: "Open Web URL"
          }, {
            type: "postback",
            title: "Trigger Postback",
            payload: "DEVELOPED_DEFINED_PAYLOAD"
          }, {
            type: "phone_number",
            title: "Call Phone Number",
            payload: "+16505551234"
          }]
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a Structured Message (Generic Message type) using the Send API.
 *
 */
function sendGenericMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "generic",
          elements: [{
            title: "rift",
            subtitle: "Next-generation virtual reality",
            item_url: "https://www.oculus.com/en-us/rift/",
            image_url: "http://messengerdemo.parseapp.com/img/rift.png",
            buttons: [{
              type: "web_url",
              url: "https://www.oculus.com/en-us/rift/",
              title: "Open Web URL"
            }, {
              type: "postback",
              title: "Call Postback",
              payload: "Payload for first bubble",
            }],
          }, {
            title: "touch",
            subtitle: "Your Hands, Now in VR",
            item_url: "https://www.oculus.com/en-us/touch/",
            image_url: "http://messengerdemo.parseapp.com/img/touch.png",
            buttons: [{
              type: "web_url",
              url: "https://www.oculus.com/en-us/touch/",
              title: "Open Web URL"
            }, {
              type: "postback",
              title: "Call Postback",
              payload: "Payload for second bubble",
            }]
          }]
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a receipt message using the Send API.
 *
 */
function sendReceiptMessage(recipientId) {
  // Generate a random receipt ID as the API requires a unique ID
  var receiptId = "order" + Math.floor(Math.random() * 1000);

  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "receipt",
          recipient_name: "Peter Chang",
          order_number: receiptId,
          currency: "USD",
          payment_method: "Visa 1234",
          timestamp: "1428444852",
          elements: [{
            title: "Oculus Rift",
            subtitle: "Includes: headset, sensor, remote",
            quantity: 1,
            price: 599.00,
            currency: "USD",
            image_url: "http://messengerdemo.parseapp.com/img/riftsq.png"
          }, {
            title: "Samsung Gear VR",
            subtitle: "Frost White",
            quantity: 1,
            price: 99.99,
            currency: "USD",
            image_url: "http://messengerdemo.parseapp.com/img/gearvrsq.png"
          }],
          address: {
            street_1: "1 Hacker Way",
            street_2: "",
            city: "Menlo Park",
            postal_code: "94025",
            state: "CA",
            country: "US"
          },
          summary: {
            subtotal: 698.99,
            shipping_cost: 20.00,
            total_tax: 57.67,
            total_cost: 626.66
          },
          adjustments: [{
            name: "New Customer Discount",
            amount: -50
          }, {
            name: "$100 Off Coupon",
            amount: -100
          }]
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a message with Quick Reply buttons.
 *
 */
function sendQuickReply(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: "What's your favorite movie genre?",
      metadata: "DEVELOPER_DEFINED_METADATA",
      quick_replies: [{
          "content_type": "text",
          "title": "Action",
          "payload": "DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_ACTION"
        },
        {
          "content_type": "text",
          "title": "Comedy",
          "payload": "DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_COMEDY"
        },
        {
          "content_type": "text",
          "title": "Drama",
          "payload": "DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_DRAMA"
        }
      ]
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a read receipt to indicate the message has been read
 *
 */
function sendReadReceipt(recipientId) {
  console.log("Sending a read receipt to mark message as seen");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "mark_seen"
  };

  callSendAPI(messageData);
}

/*
 * Turn typing indicator on
 *
 */
function sendTypingOn(recipientId) {
  console.log("Turning typing indicator on");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "typing_on"
  };

  callSendAPI(messageData);
}

/*
 * Turn typing indicator off
 *
 */
function sendTypingOff(recipientId) {
  console.log("Turning typing indicator off");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "typing_off"
  };

  callSendAPI(messageData);
}
/*
 * send quiz
 */
function sendQuiz(recipientId, quizMessage, correctAnswer) {
  var messageMetaData;
  switch (correctAnswer) {
    case 1:
      messageMetaData = "1";
      break;
    case 2:
      messageMetaData = "2";
      break;
    case 3:
      messageMetaData = "3";
      break;
    case 4:
      messageMetaData = "4";
      break;
    default:

  }
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: quizMessage,
      metadata: messageMetaData,
      quick_replies: [{
          "content_type": "text",
          "title": "1",
          "payload": messageMetaData
        },
        {
          "content_type": "text",
          "title": "2",
          "payload": messageMetaData
        },
        {
          "content_type": "text",
          "title": "3",
          "payload": messageMetaData
        },
        {
          "content_type": "text",
          "title": "4",
          "payload": messageMetaData
        }
      ]
    }
  };

  callSendAPI(messageData);
}

/*
 * Call the Send API. The message data goes in the body. If successful, we'll
 * get the message id in a response
 *
 */
function callSendAPI(messageData) {
  request({
    uri: 'https://graph.facebook.com/v2.10/me/messages',
    qs: {
      access_token: PAGE_ACCESS_TOKEN
    },
    method: 'POST',
    json: messageData

  }, function(error, response, body) {
    if (!error && response.statusCode == 200) {
      var recipientId = body.recipient_id;
      var messageId = body.message_id;

      if (messageId) {
        console.log("Successfully sent message with id %s to recipient %s",
          messageId, recipientId);
      } else {
        console.log("Successfully called Send API for recipient %s",
          recipientId);
      }
    } else {
      //  var errorMessage = response.error.message;
      //  var errorCode = response.error.code;
      console.error("Unable to send message. Error :" + JSON.stringify(error));
    }
  });
}


function callPrivateReplyAPI(commentId, message) {
  request({
    uri: 'https://graph.facebook.com/v2.10/' + commentId + '/private_replies',
    qs: {
      access_token: "EAADsma3b8o8BACZBboH0QqyJicCaoob9kzyF2KfsAPH7aSSZAM5S2DRGLSvg9kShQZBBJtp3p6JI7Y0RT6Lsi1vwLw4nPWyrI3TqZC9qtsqwGL6XiyHnYtDEXpXFCI6fqJwFO1tIsrVbKQdHhPwgNxhD77sBZC7TNvpZCi0xglZBQZDZD",
      message: message
    },
    method: 'POST'
  }, function(error, response, body) {
    if (!error) {
      var messageId = body.id;

      if (messageId) {
        console.log("Successfully sent message with id %s",
          messageId);
      }
    } else {
      //  var errorMessage = response.error.message;
      //  var errorCode = response.error.code;
      console.error("Unable to send message. Error :" + JSON.stringify(error));
    }
  });
}

function callCommentsReplyAPI(commentId, message) {
  request({
    uri: 'https://graph.facebook.com/v2.10/' + commentId + '/comments',
    qs: {
      access_token: "EAADsma3b8o8BACZBboH0QqyJicCaoob9kzyF2KfsAPH7aSSZAM5S2DRGLSvg9kShQZBBJtp3p6JI7Y0RT6Lsi1vwLw4nPWyrI3TqZC9qtsqwGL6XiyHnYtDEXpXFCI6fqJwFO1tIsrVbKQdHhPwgNxhD77sBZC7TNvpZCi0xglZBQZDZD",
      message: message
    },
    method: 'POST'
  }, function(error, response, body) {
    if (!error) {
      var messageId = body.id;

      if (messageId) {
        console.log("Successfully sent message with id %s",
          messageId);
      }
    } else {
      //  var errorMessage = response.error.message;
      //  var errorCode = response.error.code;
      console.error("Unable to send message. Error :" + JSON.stringify(error));
    }
  });
}

/*
 * cloud code from parse server
 *
 */
function callParseServerCloudCode(methodName, requestMsg, responseMsg) {
  console.log("callParseServerCloudCode:" + methodName + "\nrequestMsg:" + requestMsg);
  var options = {
    url: 'https://reply-msg-parse-server.herokuapp.com/parse/functions/' + methodName,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Parse-Application-Id': 'myAppId',
      'X-Parse-REST-API-Key': 'myRestKey'
    },
    body: requestMsg
  };

  function callback(error, response, body) {
    console.log("response:" + JSON.stringify(response));
    if (!error && response.statusCode == 200) {
      var info = JSON.parse(body);
      responseMsg(info.result.replyMsg);
      console.log("result.msg: " + info.result.msg + " result.replyMsg: " + info.result.replyMsg);
    } else {
      console.error("Unable to send message. Error :" + error);
    }
  }
  request(options, callback);
}

function sendHelpTips(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: "อยากรู้วิธีสั่งข้ารึ จะให้ข้าทำอะไร?",
      metadata: "DEVELOPER_DEFINED_METADATA",
      quick_replies: [{
          "content_type": "text",
          "title": "สอนข้า",
          "payload": "DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_ACTION"
        },
        {
          "content_type": "text",
          "title": "ส่งข้อความ",
          "payload": "DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_ACTION"

        }
      ]
    }
  };

  callSendAPI(messageData);
}

function sendMenu(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Menu",
          buttons: [{
            type: "web_url",
            url: "https://www.oculus.com/en-us/rift/",
            title: "Open Web URL"
          }, {
            type: "postback",
            title: "Trigger Postback",
            payload: "DEVELOPED_DEFINED_PAYLOAD"
          }, {
            type: "phone_number",
            title: "Call Phone Number",
            payload: "+16505551234"
          }]
        }
      }
    }
  };

  callSendAPI(messageData);
}

function processMessage(reqMsg, resMsg) {
  if (reqMsg.length > 6) {
    var checkMsg = reqMsg.substring(0, 4);
    switch (checkMsg) {
      case '#ask':
        // trainingCommand
        trainingCommand(reqMsg, function(res) {
          if (!res) {
            resMsg("ข้าว่ามีบางอย่างผิดพลาด ลองใหม่ซิ");
            //failed
          } else {
            resMsg("ข้าจำได้แล้ว ลองทักข้าใหม่ซิ อิอิ");
            //success
          }
        });
        break;
      case '#bot':
        // botCommand
        resMsg("bot command");

        break;

      default:
        resMsg(reqMsg);
    }
  } else {
    // return original msg
    resMsg(reqMsg);
  }
}

function trainingCommand(msg, res) {
  msg = msg.replace("#ask ", "");
  msg = msg.replace(" #ans ", ":");
  var msgs = msg.split(":");
  var replyDatas = msgs[1].split(",");
  replyDatas = JSON.stringify(replyDatas);
  var data = '{"msg":"' + msgs[0] + '","replyMsg":' + replyDatas + '}';
  callParseServerCloudCode("botTraining", data, function(response) {
    console.log(response);
    res(response);
  });
}

function isBotCommand(msg, res) {
  if (msg.length > 6) {
    if (msg.substring(0, 4) == "#bot") {
      res(true);
    } else {
      res(false);
    }
  } else {
    res(false);
  }
}


// Start server
// Webhooks must be available via SSL with a certificate signed by a valid
// certificate authority.
app.listen(app.get('port'), function() {
  console.log('Node app is running on port', app.get('port'));
});

module.exports = app;
