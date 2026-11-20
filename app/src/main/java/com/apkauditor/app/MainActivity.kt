package com.apkauditor.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.runtime.Composable
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.apkauditor.app.ui.AuditViewModel
import com.apkauditor.app.ui.HomeScreen
import com.apkauditor.app.ui.ReportScreen
import com.apkauditor.app.ui.theme.AuditorTheme

class MainActivity : ComponentActivity() {

    private val viewModel: AuditViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            AuditorTheme {
                AppNav(viewModel)
            }
        }
    }

    override fun onDestroy() {
        viewModel.onAppClosing()
        super.onDestroy()
    }
}

@Composable
private fun AppNav(viewModel: AuditViewModel) {
    val nav = rememberNavController()
    NavHost(nav, startDestination = "home") {
        composable("home") {
            HomeScreen(
                viewModel = viewModel,
                onOpenReport = { id -> nav.navigate("report/$id") }
            )
        }
        composable(
            "report/{id}",
            arguments = listOf(navArgument("id") { type = NavType.LongType })
        ) { backStack ->
            ReportScreen(
                auditId = backStack.arguments?.getLong("id") ?: -1,
                viewModel = viewModel,
                onBack = { nav.popBackStack() }
            )
        }
    }
}
