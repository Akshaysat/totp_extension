import streamlit as st
import os
import asyncio
from pymongo import MongoClient, DESCENDING
import pandas as pd

from session_state import get
from httpx_oauth.clients.google import GoogleOAuth2

st.markdown(
    "<h1 style='text-align: center; color: black;'>TOTP Automation - User Dashboard</h1>",
    unsafe_allow_html=True,
)

st.write("")
st.write("")


# Google Authentication Code
async def write_authorization_url(client, redirect_uri):
    authorization_url = await client.get_authorization_url(
        redirect_uri,
        scope=["profile", "email"],
        extras_params={"access_type": "offline"},
    )
    return authorization_url


async def write_access_token(client, redirect_uri, code):
    token = await client.get_access_token(code, redirect_uri)
    return token


async def get_email(client, token):
    user_id, user_email = await client.get_id_email(token)
    return user_id, user_email


def main(user_id, user_email):
    st.write(f"You're logged in as {user_email}")


if __name__ == "__main__":

    client_id = st.secrets["GOOGLE_CLIENT_ID"]
    client_secret = st.secrets["GOOGLE_CLIENT_SECRET"]
    redirect_uri = st.secrets["REDIRECT_URI"]

    client = GoogleOAuth2(client_id, client_secret)
    authorization_url = asyncio.run(
        write_authorization_url(client=client, redirect_uri=redirect_uri)
    )

    session_state = get(token=None)
    if session_state.token is None:
        try:
            code = st.experimental_get_query_params()["code"]
        except:
            st.markdown(
                f"[![Login with google](https://s3.ap-south-1.amazonaws.com/messenger.prod.learnapp.com/emails/newsLetters-09-mar-23-breaking-email-test/4371477b-6acd-4577-bc2f-c638bdbbe215.png)]({authorization_url})"
            )
            # st.write(
            #     f"""<h1>
            #     Please login using this <a target="_self"
            #     href="{authorization_url}">url</a></h1>""",
            #     unsafe_allow_html=True,
            # )
        else:
            # Verify token is correct:
            try:
                token = asyncio.run(
                    write_access_token(
                        client=client, redirect_uri=redirect_uri, code=code
                    )
                )
            except:
                st.write(
                    f"""<h4>
                    This account is not allowed or page was refreshed
                    : <a target="_self"
                    href="{authorization_url}">Please login again</a></h4>""",
                    unsafe_allow_html=True,
                )
            else:
                # Check if token has expired:
                if token.is_expired():
                    if token.is_expired():
                        st.write(
                            f"""<h1>
                        Login session has ended,
                        please <a target="_self" href="{authorization_url}">
                        login</a> again.</h1>
                        """
                        )
                else:
                    session_state.token = token
                    user_id, user_email = asyncio.run(
                        get_email(client=client, token=token["access_token"])
                    )
                    session_state.user_id = user_id
                    session_state.user_email = user_email
                    main(
                        user_id=session_state.user_id,
                        user_email=session_state.user_email,
                    )

                    mongo_url = st.secrets["mongo_db"]["mongo_url"]
                    mongo = MongoClient(mongo_url)
                    mydb = mongo["test"]
                    coll = mydb["totp-automation"]

                    action = st.selectbox(
                        "Do you want to integrate a new account or update totp details of previously added accounts",
                        ("Integrate New Account", "Update TOTP Key"),
                    )

                    st.write("----")

                    if action == "Integrate New Account":
                        broker = st.selectbox(
                            "Please Select your broker", ("Zerodha", "Fyers")
                        )

                        user_id = st.text_input(
                            "Please Enter your User ID", key="user_id"
                        )
                        totp_key = st.text_input(
                            "Please Enter your TOTP Key", key="totp_key"
                        )

                        if st.button("Integrate Broker"):
                            totp_details = []
                            totp_details.append(
                                {
                                    "email_id": session_state.user_email,
                                    "broker_name": broker,
                                    "user_id": user_id,
                                    "totp_key": totp_key,
                                }
                            )

                            coll.insert_many(totp_details)

                        st.header("Your Accounts")
                        df = pd.DataFrame(
                            list(coll.find({"email_id": session_state.user_email})),
                            columns=["broker_name", "user_id", "totp_key"],
                        )
                        st.table(df)

                    elif action == "Update TOTP Key":
                        user_id_keys = []

                        for i in list(
                            coll.find({"email_id": session_state.user_email})
                        ):
                            user_id_keys.append(i["user_id"])

                        user_id = st.selectbox("Please Select user_id", user_id_keys)
                        totp_key = st.text_input(
                            "Please Enter your new TOTP Key", key="totp_key"
                        )

                        if st.button("Update TOTP Key"):
                            myquery = {
                                "email_id": session_state.user_email,
                                "user_id": user_id,
                            }
                            newvalues = {"$set": {"totp_key": totp_key}}
                            coll.update_one(myquery, newvalues)

                        df = pd.DataFrame(
                            list(coll.find({"email_id": session_state.user_email})),
                            columns=["broker_name", "user_id", "totp_key"],
                        )
                        st.table(df)

    else:

        main(user_id=session_state.user_id, user_email=session_state.user_email)

        mongo_url = st.secrets["mongo_db"]["mongo_url"]
        mongo = MongoClient(mongo_url)
        mydb = mongo["test"]
        coll = mydb["totp-automation"]

        action = st.selectbox(
            "Do you want to integrate a new account or update totp details of previously added accounts",
            ("Integrate New Account", "Update TOTP Key"),
        )

        st.write("----")

        if action == "Integrate New Account":
            broker = st.selectbox("Please Select your broker", ("Zerodha", "Fyers"))

            user_id = st.text_input("Please Enter your User ID", key="user_id")
            totp_key = st.text_input("Please Enter your TOTP Key", key="totp_key")

            if st.button("Integrate Broker"):
                totp_details = []
                totp_details.append(
                    {
                        "email_id": session_state.user_email,
                        "broker_name": broker,
                        "user_id": user_id,
                        "totp_key": totp_key,
                    }
                )

                coll.insert_many(totp_details)

            st.header("Your Accounts")
            df = pd.DataFrame(
                list(coll.find({"email_id": session_state.user_email})),
                columns=["broker_name", "user_id", "totp_key"],
            )
            st.table(df)

        elif action == "Update TOTP Key":
            user_id_keys = []

            for i in list(coll.find({"email_id": session_state.user_email})):
                user_id_keys.append(i["user_id"])

            user_id = st.selectbox("Please Select user_id", user_id_keys)
            totp_key = st.text_input("Please Enter your new TOTP Key", key="totp_key")

            if st.button("Update TOTP Key"):
                myquery = {"email_id": session_state.user_email, "user_id": user_id}
                newvalues = {"$set": {"totp_key": totp_key}}
                coll.update_one(myquery, newvalues)

            st.header("Your Accounts")
            df = pd.DataFrame(
                list(coll.find({"email_id": session_state.user_email})),
                columns=["broker_name", "user_id", "totp_key"],
            )
            st.table(df)
