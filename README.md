# Auditor APK

App Android (Kotlin + Jetpack Compose, Material 3) que audita **cualquier APK**
que elijas con el selector de archivos. Todo el análisis es **solo lectura**
y corre 100% en el teléfono: sin backend, sin instalar ni ejecutar el APK.

## Qué analiza

- **Manifest** (sin instalar): paquete, versionName/versionCode, minSdk,
  targetSdk, debuggable.
- **Permisos** clasificados: normales, peligrosos (con explicación simple),
  especiales y de sistema.
- **Componentes**: Activities, Services, Receivers y Providers con su flag
  `exported`.
- **Contenido del ZIP**: código DEX, nativas por ABI, recursos, assets,
  META-INF, con tamaños.
- **Firma**: certificados (sujeto, emisor, algoritmo, SHA-256, vigencia),
  múltiples firmantes.
- **Ingeniería inversa del dex**: parsea la tabla de strings exacta
  (con respaldo a barrido en bruto). URLs `http://` validadas, IPs con
  contexto, APIs sensibles, SDKs de analítica/ads, posibles secretos
  (solo el tipo, nunca el valor) y menciones a root/análisis.
  Heurístico e informativo.
- **Manifest binario**: detecta activities lanzadoras (MAIN/LAUNCHER)
  para no castigarlas como exportadas.
- **Score 0-100** = base determinista (manifest + firma) + ajuste
  heurístico (dex, marcado como tal). Referencia fija de targetSdk,
  independiente del equipo. Fórmula documentada en
  `app/src/main/java/com/apkauditor/app/analysis/Scoring.kt`.

## Funciones

- Historial local con Room, exportar reporte a **PDF** y **Markdown** (SAF),
  borrado del temporal + limpieza automática.
- Maneja: APK corrupto, archivo no-APK, archivos de más de 500 MB.
- Español, modo claro/oscuro, 2 pantallas (Inicio, Reporte).

## Descargar el APK

Cada push a `main` compila y publica el APK:

1. Abre la pestaña **Actions** del repo.
2. Entra al último run verde de **Build APK** (corre tests + compilación).
3. Descarga el artifact **app-debug**.

Si un build falla, el workflow abre un issue con el extracto del log.

## Compilar en local

Requisitos: JDK 17 + Android SDK con `compileSdk 34`
(este equipo ARM no puede enlazar el APK: `aapt2` es x86_64; usa el CI
o un PC).

```sh
echo "sdk.dir=/ruta/a/tu/Android-Sdk" > local.properties
./gradlew testDebugUnitTest   # 31 tests unitarios puros
./gradlew assembleDebug
```

## Publicar este repo en GitHub

```sh
cd apk-auditor
# 1. Crea el repo vacío en github.com (sin README ni .gitignore)
# 2. Conecta y sube:
git remote add origin git@github.com:TU-USUARIO/apk-auditor.git
git branch -M main
git push -u origin main
```

El primer push dispara el workflow **Build APK** y en unos minutos
tienes el APK listo en Actions.

## Estructura

```
├── settings.gradle / build.gradle / gradle.properties
├── gradlew (+ gradle/wrapper)   # Gradle 8.9, AGP 8.5.2, Kotlin 1.9.24
├── app/
│   ├── build.gradle             # Compose BOM, Room, Navigation, KSP
│   └── src/
│       ├── main/java/com/apkauditor/app/
│       │   ├── MainActivity.kt  # Navegación: Inicio + Reporte
│       │   ├── model/           # Reporte y hallazgos
│       │   ├── analysis/        # ApkAnalyzer, DexParser, DexStrings, ManifestParser,
│       │   │                       # Scoring, PermissionData, Format
│       │   ├── data/            # Room, JSON (org.json), exportadores PDF/MD
│       │   └── ui/              # HomeScreen, ReportScreen, ViewModel, tema
│       └── test/                # 31 tests unitarios (JUnit4, sin emulador)
│           └── resources/       # Manifest binario real como fixture
└── .github/workflows/build-apk.yml
```
