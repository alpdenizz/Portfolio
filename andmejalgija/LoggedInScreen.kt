package com.arkadst.dataaccessnotifier.ui.screens

import android.content.Context
import android.util.Log
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.wrapContentWidth
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountBox
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.material3.pulltorefresh.PullToRefreshDefaults
import androidx.compose.material3.pulltorefresh.rememberPullToRefreshState
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.content.edit
import com.arkadst.dataaccessnotifier.R
import com.arkadst.dataaccessnotifier.Utils.pollDataTrackerUtil
import com.arkadst.dataaccessnotifier.accessLogsDataStore
import com.arkadst.dataaccessnotifier.access_logs.DataSystem
import com.arkadst.dataaccessnotifier.access_logs.LogEntryJson
import com.arkadst.dataaccessnotifier.access_logs.LogEntryManager
import com.arkadst.dataaccessnotifier.core.Constants
import com.arkadst.dataaccessnotifier.ui.components.DividerWithText
import com.arkadst.dataaccessnotifier.ui.components.FilterClass
import com.arkadst.dataaccessnotifier.ui.components.LogEntryItem
import com.arkadst.dataaccessnotifier.ui.components.VerticalScrollbar
import com.arkadst.dataaccessnotifier.userInfoDataStore
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.TimeUnit

import androidx.compose.material3.SwipeToDismissBox
import androidx.compose.material3.SwipeToDismissBoxValue
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.TabRowDefaults
import androidx.compose.material3.rememberSwipeToDismissBoxState
import androidx.compose.runtime.key
import androidx.compose.ui.text.buildAnnotatedString
import com.arkadst.dataaccessnotifier.ui.components.UserInfoText


enum class SortOption {
    RECEIVED, ACCESSED
}
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LoggedInScreen(
    modifier: Modifier = Modifier,
    onLogout: () -> Unit,
    selectUnreadTab: Boolean
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val sheetStateForSubscription = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    var showSheet by remember { mutableStateOf(false) }
    var showSheetForSubscription by remember { mutableStateOf(false) }
    var showUnreadEntriesOnly by remember { mutableStateOf(false) }
    //var selectedSort by remember { mutableStateOf(SortOption.ACCESSED) }
    //var expandedSortList by remember { mutableStateOf(false) }
    var expandedActions by remember { mutableStateOf(false) }
    var isFiltered by remember { mutableStateOf(false) }
    val firstNameFlow = remember {
        context.userInfoDataStore.data.map { userInfo ->
            userInfo.firstName
        }
    }
    val lastNameFlow = remember {
        context.userInfoDataStore.data.map { userInfo ->
            userInfo.lastName
        }
    }
    val personalCodeFlow = remember {
        context.userInfoDataStore.data.map { userInfo ->
            userInfo.personalCode
        }
    }
    val firstName by firstNameFlow.collectAsState(initial = "")
    val lastName by lastNameFlow.collectAsState(initial = "")
    val personalCode by personalCodeFlow.collectAsState(initial = "")
    var showIntervalOptions by remember { mutableStateOf(false) }

    // Use collectAsState to automatically update when new entries are added
    val logEntries by LogEntryManager.loadLogEntriesFlow(context).collectAsState(initial = emptyList())
    val informationSystems by LogEntryManager.loadDataSystemsFlow(context).collectAsState(initial = emptyList())

    //filter logEntries
    val filterOpts = remember { mutableStateOf(FilterClass()) }
    var entriesCount by remember { mutableIntStateOf(0) }

    val subscriptionOpts = remember { mutableStateListOf<String>() }
    val listState = rememberLazyListState()
    val sharedPref = context.getSharedPreferences("MyPrefs", Context.MODE_PRIVATE)
    var selectedInterval by remember {
        val selected = sharedPref.getLong("refresh_interval",0L)
        val str = if(selected == 0L) context.getString(R.string.minutes, 5) else context.getString(R.string.minutes, selected / (1000 * 60))
        mutableStateOf(str)
    }
    var lastUpdated by remember { mutableLongStateOf(System.currentTimeMillis()) }

    var refreshing by remember { mutableStateOf(false) }
    val swipeRefreshState = rememberPullToRefreshState()
    val onRefresh: () -> Unit = {
        refreshing = true
        scope.launch {
            Log.d("LoggedInScreen", "Manual refresh...")
            pollDataTrackerUtil(context)
            refreshing = false
        }
    }

    var selectedTab by remember {
        if(selectUnreadTab) {
            mutableIntStateOf(1)
        } else {
            mutableIntStateOf(0)
        }
    }


    // Update timestamp only when new log entries arrive
    LaunchedEffect(logEntries) {
        if (logEntries.isNotEmpty()) {
            lastUpdated = System.currentTimeMillis()
        }
    }

    Column(
        modifier = modifier.fillMaxSize().padding(16.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = stringResource(R.string.app_name),
                modifier = Modifier
                    .weight(1f) // Takes up remaining space
                    .padding(end = 8.dp),
                style = MaterialTheme.typography.headlineSmall
            )
            Box(
                contentAlignment = Alignment.TopEnd // Aligns content to the right
            ) {
                IconButton(onClick = { expandedActions = true }) {
                    Icon(
                        imageVector = Icons.Default.Settings,
                        contentDescription = "Account Box",
                        modifier = Modifier.size(40.dp)
                    )
                }
                DropdownMenu(
                    expanded = expandedActions,
                    onDismissRequest = { expandedActions = false }
                ) {
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.refresh)) },
                        leadingIcon = {
                            Icon(
                                imageVector = Icons.Default.Refresh,
                                contentDescription = null
                            )
                        },
                        onClick = {
                            // Handle Refresh
                            expandedActions = false
                            scope.launch {
                                Log.d("LoggedInScreen", "Manual refresh...")
                                pollDataTrackerUtil(context)
                            }
                        }
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.change_interval)) },
                        leadingIcon = {
                            Icon(
                                imageVector = Icons.Default.Settings,
                                contentDescription = null
                            )
                        },
                        onClick = {
                            // Handle Refresh
                            expandedActions = false
                            showIntervalOptions = true
                        }
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.mark_all)) },
                        leadingIcon = {
                            Icon(
                                imageVector = Icons.Default.Check,
                                contentDescription = null
                            )
                        },
                        onClick = {
                            expandedActions = false
                            scope.launch {
                                context.accessLogsDataStore.updateData { currentLogs ->
                                    val updatedLogs = currentLogs.entriesList.map { entry ->
                                        entry.toBuilder().setIsRead(true).build()
                                    }
                                    currentLogs.toBuilder()
                                        .clearEntries()
                                        .addAllEntries(updatedLogs)
                                        .build()
                                }
                            }
                        }
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.subscribe)) },
                        leadingIcon = {
                            Icon(
                                imageVector = Icons.Default.Add,
                                contentDescription = null
                            )
                        },
                        onClick = {
                            expandedActions = false
                            showSheetForSubscription = true
                        }
                    )
                    //raw json logging switch
                    DropdownMenuItem(
                        text = {
                            Row(
                                Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text("Raw JSON Logging")
                                Switch(
                                    checked = sharedPref.getBoolean("EnableRawJsonLogging", true),
                                    onCheckedChange = {
                                        sharedPref.edit {
                                            putBoolean("EnableRawJsonLogging", it)
                                        }
                                    }
                                )
                            }
                        },
                        onClick = {}
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.logout_button)) },
                        leadingIcon = {
                            Icon(
                                imageVector = Icons.Default.Close,
                                contentDescription = null
                            )
                        },
                        onClick = {
                            // Handle Logout
                            expandedActions = false
                            onLogout()
                        }
                    )
                    DropdownMenuItem(
                        text = {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Spacer(modifier = Modifier.weight(1f)) // pushes the button to the end
                                Text("Version ${stringResource(R.string.app_version)}")
                            }
                        },
                        onClick = {},
                        enabled = false
                    )
                }
                if (showIntervalOptions) {
                    DropdownMenu(
                        expanded = true,
                        onDismissRequest = { showIntervalOptions = false },
                        modifier = Modifier.align(Alignment.TopEnd) // Position second menu
                    ) {
                        DropdownMenuItem(
                            text = {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                        RadioButton(
                                            selected = (stringResource(R.string.minutes,5) == selectedInterval),
                                            onClick = {
                                                selectedInterval = context.getString(R.string.minutes,5)
                                                showIntervalOptions = false
                                                sharedPref.edit {
                                                    putLong("refresh_interval", TimeUnit.MINUTES.toMillis(5))
                                                }
                                            }
                                        )
                                        Spacer(modifier = Modifier.width(8.dp))
                                        Text(stringResource(R.string.minutes,5))
                                    }
                                   },
                            onClick = {
                                showIntervalOptions = false
                            })
                        DropdownMenuItem(
                            text = {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    RadioButton(
                                        selected = (stringResource(R.string.minutes,10) == selectedInterval),
                                        onClick = {
                                            selectedInterval = context.getString(R.string.minutes,10)
                                            showIntervalOptions = false
                                            sharedPref.edit {
                                                putLong("refresh_interval", TimeUnit.MINUTES.toMillis(10))
                                            }
                                        }
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text(stringResource(R.string.minutes,10))
                                }
                                   },
                            onClick = {
                                showIntervalOptions = false
                            })
                        DropdownMenuItem(
                            text = {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    RadioButton(
                                        selected = (stringResource(R.string.minutes,15) == selectedInterval),
                                        onClick = {
                                            selectedInterval = context.getString(R.string.minutes,15)
                                            showIntervalOptions = false
                                            sharedPref.edit {
                                                putLong("refresh_interval", TimeUnit.MINUTES.toMillis(15))
                                            }
                                        }
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text(stringResource(R.string.minutes,15))
                                }
                            },
                            onClick = {
                                showIntervalOptions = false
                            })
                        DropdownMenuItem(
                            text = {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    RadioButton(
                                        selected = (stringResource(R.string.minutes,20) == selectedInterval),
                                        onClick = {
                                            selectedInterval = context.getString(R.string.minutes,20)
                                            showIntervalOptions = false
                                            sharedPref.edit {
                                                putLong("refresh_interval", TimeUnit.MINUTES.toMillis(20))
                                            }
                                        }
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text(stringResource(R.string.minutes,20))
                                }
                                   },
                            onClick = {
                                showIntervalOptions = false
                            })
                        DropdownMenuItem(
                            text = {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    RadioButton(
                                        selected = (stringResource(R.string.minutes,25) == selectedInterval),
                                        onClick = {
                                            selectedInterval = context.getString(R.string.minutes,25)
                                            showIntervalOptions = false
                                            sharedPref.edit {
                                                putLong("refresh_interval", TimeUnit.MINUTES.toMillis(25))
                                            }
                                        }
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text(stringResource(R.string.minutes,25))
                                }
                                   },
                            onClick = {
                                showIntervalOptions = false
                            })
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        // Scrollable list of log entries
        if (logEntries.isEmpty() && informationSystems.isEmpty()) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                )
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(32.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Text(
                            text = stringResource(R.string.no_activity),
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            text = stringResource(R.string.will_appear),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        } else {
            // Log entries section with improved spacing
            Row(
                modifier = Modifier.fillMaxWidth()
            ) {
                UserInfoText(lastUpdated, firstName.uppercase(), lastName.uppercase(), personalCode)
                Spacer(modifier = Modifier.weight(1f)) // pushes the button to the end
                Button(
                    modifier = Modifier.wrapContentWidth(),
                    onClick = { showSheet = true },
                    shape = RoundedCornerShape(4.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary)
                ) {
                    //Log.d("LoggedInScreen","filtered: $isFiltered")
                    Icon(
                        painter = if(isFiltered) painterResource(id = R.drawable.filter_icon_filled) else painterResource(id = R.drawable.filter_icon),
                        contentDescription = "Filter Icon",
                        modifier = Modifier.size(20.dp),
                        tint = Color.Unspecified // Prevent theme tinting
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(text = stringResource(R.string.apply_filter), color = Color.White)
                }
            }
            if (showSheet) {

                LaunchedEffect(Unit) {
                    sheetState.show() // this will expand it fully if skipPartiallyExpanded is true
                }

                FilterBottomSheet(
                    sheetState = sheetState,
                    onApply = {
                        scope.launch { sheetState.hide() }
                        showSheet = false
                    },
                    onExit = {
                        scope.launch { sheetState.hide() }
                        showSheet = false
                    },
                    filterOptions = filterOpts,
                    informationSystems = informationSystems
                )
            }

            if (showSheetForSubscription) {

                LaunchedEffect(Unit) {
                    sheetStateForSubscription.show() // this will expand it fully if skipPartiallyExpanded is true
                }

                SubscribeBottomSheet(
                    sheetState = sheetStateForSubscription,
                    onApply = {
                        scope.launch { sheetStateForSubscription.hide() }
                        showSheetForSubscription = false
                        val subscribed = informationSystems.filter { i -> !subscriptionOpts.contains(i.key) }.map(DataSystem::key)
                        Constants.DATA_TRACKER_API_URL = Constants.dataTrackerUrl(subscribed)
                        Log.d("LoggedInScreen", "data tracker api url should be changed")
                        Log.d("LoggedInScreen", "subscription list: $subscriptionOpts")
                    },
                    onExit = {
                        scope.launch { sheetStateForSubscription.hide() }
                        showSheetForSubscription = false
                    },
                    subscriptionOptions = subscriptionOpts,
                    informationSystems = informationSystems
                )
            }

            /*
            Filtering in Eesti app:

            final filtered = _usages.where((logEntry) {

            final matchesStartDateCriteria = _filterFrom == null || logEntry.logTime.isAfter(_filterFrom!);

            final matchesEndDateCriteria =
                _filterTo == null || logEntry.logTime.isBefore(_filterTo!.add(const Duration(days: 1)));

            final matchesSearchCriteria = searchTerm == null ||
                logEntry.action.toLowerCase().contains(searchTerm) ||
                    (logEntry.receiver != null && logEntry.receiver!.contains(searchTerm));

            final matchesByMeCriteria =
                _filterMyRequests == false || logEntry.receiver == null || !logEntry.receiver!.contains(numericPersonalCode);

            return matchesStartDateCriteria && matchesEndDateCriteria && matchesSearchCriteria && matchesByMeCriteria;
            */

            fun parseDate(dateString: String): Date? {
                val format = SimpleDateFormat("dd.MM.yyyy", Locale.getDefault())
                return try {
                    format.parse(dateString)
                } catch (e: Exception) {
                    e.printStackTrace()
                    null
                }
            }

            fun compareTimestamp(filterDate: String, logDate: String): Boolean {
                val localDateFilter = parseDate(filterDate)!!
                val localDateLog = LogEntryManager.parseLogTimestamp(logDate)!!
                return localDateFilter > localDateLog
            }

            //unfill filter icon if filter options are empty
            isFiltered = filterOpts.value != FilterClass()

            val logs = logEntries.filter { item ->
                val filters = filterOpts.value
                val matchQuery = filters.searchQuery.isEmpty() ||
                        item.action.lowercase().contains(filters.searchQuery, false) ||
                            item.receiver.contains(filters.searchQuery, true)
                val byStartDate = filters.startDate.isEmpty() || !compareTimestamp(filters.startDate, item.timestamp)
                val byEndDate = filters.endDate.isEmpty() || compareTimestamp(filters.endDate, item.timestamp)
                val selectedInfoSystems = filters.selectedOptions.isEmpty() || filters.selectedOptions.map(DataSystem::key).contains(item.infoSystem)
                val unread = !showUnreadEntriesOnly || !item.isRead

                matchQuery && byStartDate && byEndDate && selectedInfoSystems && unread
            }

            /*val sortedLogs = when (selectedSort) {
                SortOption.RECEIVED -> logs.sortedByDescending { it.receivedTimestamp }
                SortOption.ACCESSED -> logs.sortedByDescending { it.timestamp }
            }*/

            entriesCount = logs.size

            fun getInfoSystemStringValue(fromKey: String) : String {
                val resId = when (fromKey) {
                    "rahvastikuregister" -> R.string.rahvastikuregister
                    "retseptikeskus" -> R.string.retseptikeskus
                    "tootuskindlustuse_andmekogu" -> R.string.tootuskindlustuse_andmekogu
                    "digiregistratuur" -> R.string.digiregistratuur
                    "sotsiaalkaitse_infosusteem" -> R.string.sotsiaalkaitse_infosusteem
                    "kinnistusraamat" -> R.string.kinnistusraamat
                    "politsei_taktikalise_juhtimise_andmekogu" -> R.string.politsei_taktikalise_juhtimise_andmekogu
                    "sotsiaalteenuste_ja_toetuste_register" -> R.string.sotsiaalteenuste_ja_toetuste_register
                    "maksukohustuslaste_register" -> R.string.maksukohustuslaste_register
                    "kutseregister" -> R.string.kutseregister
                    "pollumajandustoetuste_ja_pollumassiivide_register" -> R.string.pollumajandustoetuste_ja_pollumassiivide_register
                    "pollumajandusloomade_register" -> R.string.pollumajandusloomade_register
                    "elamislubade_ja_toolubade_register" -> R.string.elamislubade_ja_toolubade_register
                    "infosusteem_polis" -> R.string.infosusteem_polis
                    "tooinspektsiooni_tooelu_infosusteem" -> R.string.tooinspektsiooni_tooelu_infosusteem
                    else -> 0
                }
                return context.getString(resId)
            }

            val newLogs = logs.filterNot { it.isRead }
            val readLogs = logs.filter { it.isRead }
            val itemsCount = logs.size + 2
            val fn = firstName.lowercase().replaceFirstChar { it.uppercase() }
            val ln = lastName.lowercase().replaceFirstChar { it.uppercase() }

            val tabs = listOf("All (${logs.size})", "Unread (${newLogs.size})")

            PrimaryTabRow(
                selectedTabIndex = selectedTab
                ) {
                    // Content colors: strong for selected, faded for unselected
                    val selectedColor = MaterialTheme.colorScheme.onSurface
                    val unselectedColor = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
                    tabs.forEachIndexed { index, title ->
                        Tab(
                            selected = selectedTab == index,
                            onClick = { selectedTab = index },
                            selectedContentColor = selectedColor,
                            unselectedContentColor = unselectedColor,
                            text = { Text(title) }
                        )
                    }
                }
                // Show content based on selected tab
                when (selectedTab) {
                    0 -> {
                        PullToRefreshBox(
                            modifier = Modifier.fillMaxSize(),
                            state = swipeRefreshState,
                            isRefreshing = refreshing,
                            onRefresh = onRefresh,
                            indicator = {
                                PullToRefreshDefaults.Indicator(
                                    modifier = Modifier.align(Alignment.TopCenter),
                                    isRefreshing = refreshing,
                                    state = swipeRefreshState
                                )
                            }
                        ) {
                            LazyColumn(
                                modifier = Modifier.fillMaxSize().padding(
                                    top = 8.dp,
                                    bottom = 4.dp,
                                    end = 8.dp,
                                    start = 2.dp
                                ), // Push content down,
                                state = listState,
                                verticalArrangement = Arrangement.spacedBy(12.dp)
                            ) {
                                items(logs) { entry ->
                                    LogEntryItem(
                                        logEntry = entry,
                                        infoSystem = getInfoSystemStringValue(entry.infoSystem),
                                        username = "$fn $ln"
                                    )
                                }
                            }
                        }
                        // Custom scrollbar
                        VerticalScrollbar(
                            modifier = Modifier
                                .align(Alignment.CenterHorizontally)
                                .width(4.dp)
                                .fillMaxHeight(),
                            listState = listState,
                            itemsCount = itemsCount
                        )
                    }

                    1 -> {
                        PullToRefreshBox(
                            modifier = Modifier.fillMaxSize(),
                            state = swipeRefreshState,
                            isRefreshing = refreshing,
                            onRefresh = onRefresh,
                            indicator = {
                                PullToRefreshDefaults.Indicator(
                                    modifier = Modifier.align(Alignment.TopCenter),
                                    isRefreshing = refreshing,
                                    state = swipeRefreshState
                                )
                            }
                        ) {
                        LazyColumn(
                            modifier = Modifier.fillMaxSize().padding(
                                top = 8.dp,
                                bottom = 4.dp,
                                end = 8.dp,
                                start = 2.dp
                            ), // Push content down,
                            state = listState,
                            verticalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            items(items = newLogs, key = { it.identifier }) { entry ->
                                //surround it with swipe box
                                val state = rememberSwipeToDismissBoxState(
                                    // Handle the swipe action and decide whether to complete the dismiss animation
                                    confirmValueChange = { target ->
                                        // Don’t launch coroutines here; just allow/deny
                                        target == SwipeToDismissBoxValue.StartToEnd ||
                                                target == SwipeToDismissBoxValue.EndToStart
                                    }

                                )

                                LaunchedEffect(state.currentValue) {
                                    if (state.currentValue == SwipeToDismissBoxValue.StartToEnd ||
                                        state.currentValue == SwipeToDismissBoxValue.EndToStart
                                    ) {
                                        scope.launch {
                                            Log.d(
                                                "LoggedInScreen",
                                                "$entry is read: ${entry.isRead}, identifier: ${entry.identifier}"
                                            )

                                            if (entry.isRead) return@launch

                                            val updatedEntry =
                                                entry.toBuilder().setIsRead(true).build()
                                            context.accessLogsDataStore.updateData { currentLogs ->
                                                val updatedLogs =
                                                    currentLogs.entriesList.toMutableList()
                                                val entryClicked =
                                                    updatedLogs.find { entryProto -> entryProto.identifier == entry.identifier }
                                                val entry2 = entryClicked!!
                                                Log.d(
                                                    "LoggedInScreen",
                                                    "$entry2 is read: ${entry2.isRead}"
                                                )
                                                updatedLogs.remove(entryClicked)
                                                updatedLogs.add(updatedEntry)
                                                currentLogs.toBuilder()
                                                    .clearEntries()
                                                    .addAllEntries(updatedLogs)
                                                    .build()
                                            }
                                        }

                                    }
                                }

                                SwipeToDismissBox(
                                    state = state,
                                    // Set which directions are allowed (optional; both true by default)
                                    enableDismissFromStartToEnd = true,
                                    enableDismissFromEndToStart = true,
                                    backgroundContent = {},
                                    content = {
                                        LogEntryItem(
                                            logEntry = entry,
                                            infoSystem = getInfoSystemStringValue(entry.infoSystem),
                                            username = "$fn $ln"
                                        )
                                    }
                                )
                            }
                        }
                        }
                        // Custom scrollbar
                        VerticalScrollbar(
                            modifier = Modifier
                                .align(Alignment.CenterHorizontally)
                                .width(4.dp)
                                .fillMaxHeight(),
                            listState = listState,
                            itemsCount = itemsCount
                        )
                    }
                }
                }
            }
        }