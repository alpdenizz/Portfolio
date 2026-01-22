package com.arkadst.dataaccessnotifier

import android.content.Context
import android.util.Log
import androidx.datastore.core.DataStore
import androidx.datastore.core.IOException
import androidx.datastore.core.handlers.ReplaceFileCorruptionHandler
import androidx.datastore.dataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import com.arkadst.dataaccessnotifier.access_logs.AccessLogsSerializer
import com.arkadst.dataaccessnotifier.access_logs.DataSystem
import com.arkadst.dataaccessnotifier.access_logs.LogEntryManager
import com.arkadst.dataaccessnotifier.access_logs.StoredAccessLogManager
import com.arkadst.dataaccessnotifier.auth.SessionManagementCookieJar
import com.arkadst.dataaccessnotifier.core.Constants.DATA_SYSTEMS_URL
import com.arkadst.dataaccessnotifier.core.Constants.DATA_TRACKER_API_URL
import com.arkadst.dataaccessnotifier.user_info.UserInfoManager
import com.arkadst.dataaccessnotifier.user_info.UserInfoSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.Json.Default.parseToJsonElement
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject
import okhttp3.RequestBody
import java.util.concurrent.TimeUnit
import okhttp3.logging.HttpLoggingInterceptor
import kotlin.collections.map

const val RETRIES_KEY = "retries"
private const val COOKIE_PREFS = "auth_cookies"

private const val DATA_SYSTEMS = "data_systems"

val Context.cookieDataStore: DataStore<Preferences> by preferencesDataStore(name = COOKIE_PREFS)

val Context.dataSystems: DataStore<Preferences> by preferencesDataStore(name = DATA_SYSTEMS)
val Context.userInfoDataStore: DataStore<UserInfoProto> by dataStore(
    fileName = "user_info.pb",
    serializer = UserInfoSerializer,
    corruptionHandler = ReplaceFileCorruptionHandler {
        Log.w("DataStore", "UserInfo proto corruption detected, resetting to default")
        UserInfoProto.getDefaultInstance()
    }
)
val Context.accessLogsDataStore: DataStore<AccessLogsProto> by dataStore(
    fileName = "access_logs.pb",
    serializer = AccessLogsSerializer,
    corruptionHandler = ReplaceFileCorruptionHandler {
        Log.w("DataStore", "AccessLogs proto corruption detected, resetting to default")
        AccessLogsProto.getDefaultInstance()
    }
)

private const val TAG = "getURL"

object Utils {

    suspend fun pollDataTrackerUtil(context: Context) : Boolean {
        val (code, responseBody) = getURL(context, DATA_SYSTEMS_URL)
        if (code == 200) {
            val dataSystems = parseDataSystemsResponseBody(responseBody)
            handleParsedDataSystems(context, dataSystems)
        } else {
            Log.e(TAG, "Data systems API call failed: $code")
            return false
        }
        //prepare URL with subscribed data systems
        val (statusCode, body) = getURL(context, DATA_TRACKER_API_URL)
        if (statusCode == 200) {
            Log.d(TAG, "Data tracker response: $body")
            handleParsedEntries(context,parseDataTrackerResponseBody(context,body))
            return true
        } else {
            Log.e(TAG, "Data tracker API call failed: $statusCode")
            return false
        }
    }

    private fun parseDataSystemsResponseBody(body: String) : List<DataSystem> {
        //parse data systems response to DataSystems list, use list values in filter UI and subscription UI
        parseToJsonElement(body).let { jsonElement : JsonElement ->
            if (jsonElement is JsonArray) {
                return jsonElement.map { dataSystem ->
                    val key = dataSystem.jsonObject["key"]?.toString() ?: ""
                    val enValue = dataSystem.jsonObject["enValue"]?.toString() ?: ""
                    val etValue = dataSystem.jsonObject["etValue"]?.toString() ?: ""
                    DataSystem(key,enValue,etValue)
                }
            } else {
                Log.e(TAG, "Expected JsonArray but got ${jsonElement.javaClass}")
            }
        }
        return emptyList()
    }

    private suspend fun parseDataTrackerResponseBody(context: Context, body: String) : List<LogEntryProto> {
        // Implement your parsing logic here
        parseToJsonElement(body).let { jsonElement : JsonElement ->
            jsonElement.jsonObject["findUsageResponses"]?.let { entries ->
                if (entries is JsonArray) {
                    return LogEntryManager.parseLogEntries(entries).filterNot { entry : LogEntryProto ->
                        val userInfo = UserInfoManager.getUserInfo(context)
                        entry.receiver.contains(userInfo.personalCode)
                    }
                } else {
                    Log.e(TAG, "Expected JsonArray but got ${entries.javaClass}")
                }
            }
        }
        return emptyList()
    }

    private suspend fun handleParsedDataSystems(context: Context, dataSystems: List<DataSystem>) {
        context.dataSystems.edit { prefs ->
            dataSystems.forEach { item ->
                val key = stringPreferencesKey(item.key)
                val str = Json.encodeToString(item)
                prefs[key] = str
            }
        }
    }

    private suspend fun handleParsedEntries(context: Context, entries: List<LogEntryProto>) {
        // Add new entries to storage
        StoredAccessLogManager.addAccessLogs(context, entries)
        UserInfoManager.setFirstUse(context, false)
    }

    suspend fun getURL(context: Context, url: String): Pair<Int, String> {
        return withContext(Dispatchers.IO) {
            try {
                Log.d(TAG, "Starting API test request to: $url")

                val logging = HttpLoggingInterceptor().apply {
                    level = HttpLoggingInterceptor.Level.HEADERS // Options: NONE, BASIC, HEADERS, BODY
                }

                val cookieJar = SessionManagementCookieJar(context)
                val client = okhttp3.OkHttpClient.Builder()
                    .cookieJar(cookieJar)
                    .addInterceptor(logging)
                    .build()

                val request = okhttp3.Request.Builder()
                    .url(url)
                    .build()

                client.newCall(request).execute().use { response ->
                    if (response.code !in 500..599) {
                        Log.d(TAG, "Saving ${cookieJar.cookieBuffer.size} cookies")
                        context.cookieDataStore.edit { prefs ->
                            cookieJar.cookieBuffer.forEach { (key, value) ->
                                prefs[key] = value
                            }
                        }
                    }

                    val returnValue = Pair(response.code, response.body.string())
                    Log.d(TAG, "API Response Code: ${returnValue.first}")
                    Log.d(TAG, "API Response: ${returnValue.second}")

                    return@withContext returnValue
                }

            } catch (ex: IOException) {
                Log.e(TAG, "Error during API request: ${ex.message}")
                delay(TimeUnit.SECONDS.toMillis(10))
                return@withContext getURL(context, url)
            }

        }
    }
    //postURL for refresh token endpoint
    suspend fun postURL(context: Context, url: String): Pair<Int, String> {
        return withContext(Dispatchers.IO) {
            try {
                Log.d("postURL", "Starting API test request to: $url")

                val sharedPref = context.getSharedPreferences("MyPrefs", Context.MODE_PRIVATE)

                val logging = HttpLoggingInterceptor().apply {
                    level = HttpLoggingInterceptor.Level.HEADERS // Options: NONE, BASIC, HEADERS, BODY
                }

                val cookieJar = SessionManagementCookieJar(context)
                val client = okhttp3.OkHttpClient.Builder()
                    .cookieJar(cookieJar)
                    .addInterceptor(logging)
                    .build()

                // Create an empty request body
                val requestBody = RequestBody.create(null,"")

                val agent = sharedPref.getString("user_agent", "") ?: ""
                val request = okhttp3.Request.Builder()
                    .url(url)
                    .header("User-Agent", agent)
                    .post(requestBody)
                    .build()

                client.newCall(request).execute().use { response ->
                    if (response.code !in 500..599) {
                        Log.d(TAG, "Saving ${cookieJar.cookieBuffer.size} cookies")
                        context.cookieDataStore.edit { prefs ->
                            cookieJar.cookieBuffer.forEach { (key, value) ->
                                prefs[key] = value
                            }
                        }
                    }

                    val returnValue = Pair(response.code, response.body.string())
                    Log.d(TAG, "API Response Code: ${returnValue.first}")
                    Log.d(TAG, "API Response: ${returnValue.second}")

                    return@withContext returnValue
                }

            } catch (ex: IOException) {
                Log.e(TAG, "Error during API request: ${ex.message}")
                return@withContext Pair(500, "")
            }

        }
    }
}