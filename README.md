# ZOVYA_Gifts backend — Maven ke bina

Yeh chhota Java backend aapke project ke HTML pages ko `http://localhost:8000` par kholta hai aur signup ke name, email, phone, aur password ko MySQL mein save karta hai. Password database mein asli text ke roop mein nahi, secure hash ke roop mein save hota hai. Login, current account (`/api/me`) aur logout bhi included hain.

## Ek baar ki taiyari

1. `lib` folder ke andar MySQL Connector/J JAR rakhein. Official download page: https://dev.mysql.com/downloads/connector/j/ .
2. `database.properties` mein MySQL connection details rakhein. Yeh file Git se ignore hoti hai; password is file mein hi rakhein.
3. Project folder mein `run-backend.bat` double-click karein. Backend start hone par website `http://localhost:8000/Sign_Up.HTML` par kholiye.

## Agar `mysql-connector-j-26.10.0.jar` pehle se download hai

Use seedha project ke `lib` folder mein copy karein. Agar uska version number alag hai, file ka naam upar wale naam jaisa karein; JAR ke andar ka content badalne ki zaroorat nahi.

## Dhyan rahe

- Maven install karne ki zaroorat nahi. `.bat` file JDK ke `javac` aur `java` se chalti hai.
- MySQL Server service bhi chalni chahiye. Backend pehli baar `zovya_gifts` database aur `user_accounts` table banane ki koshish karta hai; iske liye MySQL user ko database banane ki permission chahiye.
- Forgot Password code email ya SMS se bhejne ke liye neeche diye gaye provider credentials bharne honge.
- Backend chalte waqt uski terminal window khuli rakhein. Website `http://localhost:8000/ZOVYA.HTML` par bhi khul sakti hai.

## Forgot Password: email aur SMS OTP

`database.properties` mein provider settings bharne ke baad backend restart karein.

- **Gmail email:** `smtp.username` mein OTP bhejne wala Gmail address aur `smtp.appPassword` mein Google App Password rakhein. `smtp.from` khaali chhodne par `smtp.username` sender hoga. Google App Password ke liye Google Account par 2-Step Verification chalu hona zaroori hai: https://support.google.com/mail/answer/185833 .
- **Twilio SMS:** Twilio Console se `twilio.accountSid`, `twilio.authToken`, aur `twilio.from` bharein. Agar Messaging Service use karte hain to `twilio.messagingServiceSid` bharein; `from` ya Messaging Service SID mein se ek chahiye. Twilio trial account mein recipient phone ko pehle verify karna hota hai: https://www.twilio.com/docs/messaging/api/message-resource .
- Signup ke waqt registered phone number 10-digit Indian mobile ho sakta hai; backend SMS ke liye `+91` jodta hai. International number ho to `+` country code ke saath save karein.
- OTP 10 minute ke liye valid hai. Galat code ki 5 koshishon ke baad naya code mangwana padega; dobara code mangwane se pehle 1 minute rukna hoga.
- Twilio SMS par provider ke charges/account limits lagu ho sakte hain. App Password aur Twilio secrets `database.properties` mein hi rakhein; unhe chat mein share na karein.
