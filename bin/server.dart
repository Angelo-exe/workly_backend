import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

const int port = 8080;
const int maxJsonBodyBytes = 12 * 1024 * 1024;
final Directory dataDir = Directory('data');
final Directory uploadsDir = Directory('uploads');
final File companiesFile = File('data/companies.json');
final File jobsFile = File('data/jobs.json');
final File applicationsFile = File('data/applications.json');

final Map<String, String> sessions = {}; // token -> companyId

class PayloadTooLargeException implements Exception {
  const PayloadTooLargeException();
}

Future<void> main() async {
  await dataDir.create(recursive: true);
  await uploadsDir.create(recursive: true);
  for (final file in [companiesFile, jobsFile, applicationsFile]) {
    if (!await file.exists()) await file.writeAsString('[]');
  }

  final server = await HttpServer.bind(InternetAddress.anyIPv4, port);
  print('Workly API in ascolto su http://0.0.0.0:$port');
  print('Dati: ${Directory.current.path}/data');
  print('Curriculum: ${Directory.current.path}/uploads');

  await for (final request in server) {
    unawaited(
        _handle(request).catchError((Object error, StackTrace stack) async {
      stderr.writeln('Errore API: $error\n$stack');
      try {
        if (error is PayloadTooLargeException) {
          await _json(
              request.response, 413, {'error': 'Richiesta troppo grande.'});
        } else {
          await _json(
              request.response, 500, {'error': 'Errore interno del server'});
        }
      } catch (responseError) {
        stderr.writeln(
            'Impossibile inviare la risposta di errore: $responseError');
      }
    }));
  }
}

Future<List<Map<String, dynamic>>> _readList(File file) async {
  final raw = await file.readAsString();
  final decoded = jsonDecode(raw);
  return (decoded as List)
      .map((e) => Map<String, dynamic>.from(e as Map))
      .toList();
}

Future<void> _writeList(File file, List<Map<String, dynamic>> rows) async {
  // Scrittura diretta: evita il problema di File.rename quando il file di
  // destinazione esiste già (comportamento diverso su Windows).
  await file.writeAsString(
    const JsonEncoder.withIndent('  ').convert(rows),
    flush: true,
  );
}

String _id() =>
    '${DateTime.now().microsecondsSinceEpoch}_${Random.secure().nextInt(1 << 32)}';

String _hash(String password) =>
    sha256.convert(utf8.encode(password)).toString();

String? _bearer(HttpRequest request) {
  final value = request.headers.value(HttpHeaders.authorizationHeader);
  if (value == null || !value.startsWith('Bearer ')) return null;
  return value.substring(7);
}

String? _companyId(HttpRequest request) {
  final token = _bearer(request);
  return token == null ? null : sessions[token];
}

Future<Map<String, dynamic>> _body(HttpRequest request) async {
  if (request.contentLength > maxJsonBodyBytes) {
    throw const PayloadTooLargeException();
  }
  final builder = BytesBuilder(copy: false);
  var received = 0;
  await for (final chunk in request) {
    received += chunk.length;
    if (received > maxJsonBodyBytes) {
      throw const PayloadTooLargeException();
    }
    builder.add(chunk);
  }
  final bytes = builder.takeBytes();
  if (bytes.isEmpty) return {};
  return Map<String, dynamic>.from(jsonDecode(utf8.decode(bytes)) as Map);
}

Future<void> _json(HttpResponse response, int status, Object body) async {
  response.statusCode = status;
  response.headers.contentType = ContentType.json;
  response.headers.set('Access-Control-Allow-Origin', '*');
  response.headers
      .set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  response.headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  response.write(jsonEncode(body));
  await response.close();
}

Future<void> _handle(HttpRequest req) async {
  req.response.headers.set('Access-Control-Allow-Origin', '*');
  req.response.headers
      .set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  req.response.headers
      .set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method == 'OPTIONS') {
    req.response.statusCode = HttpStatus.noContent;
    await req.response.close();
    return;
  }

  final path = req.uri.path;
  final method = req.method;

  if (method == 'GET' && path == '/api/health') {
    return _json(req.response, 200, {'status': 'ok', 'app': 'Workly'});
  }

  if (method == 'POST' && path == '/api/register') {
    final b = await _body(req);
    final companyName = (b['companyName'] ?? '').toString().trim();
    final email = (b['email'] ?? '').toString().trim().toLowerCase();
    final password = (b['password'] ?? '').toString();
    final validEmail = RegExp(r'^[^@\s]+@[^@\s]+\.[^@\s]+$').hasMatch(email);
    if (companyName.isEmpty || !validEmail || password.length < 6) {
      return _json(req.response, 400, {
        'error':
            'Inserisci un nome azienda, un indirizzo email valido e una password di almeno 6 caratteri'
      });
    }
    final companies = await _readList(companiesFile);
    if (companies.any((c) => c['email'] == email)) {
      return _json(req.response, 409, {'error': 'Email già registrata'});
    }
    companies.add({
      'id': _id(),
      'companyName': companyName,
      'email': email,
      'passwordHash': _hash(password),
      'createdAt': DateTime.now().toIso8601String()
    });
    await _writeList(companiesFile, companies);
    return _json(req.response, 201, {'message': 'Account creato'});
  }

  if (method == 'POST' && path == '/api/login') {
    final b = await _body(req);
    final email = (b['email'] ?? '').toString().trim().toLowerCase();
    final password = (b['password'] ?? '').toString();
    final companies = await _readList(companiesFile);
    final matches = companies.where(
        (c) => c['email'] == email && c['passwordHash'] == _hash(password));
    if (matches.isEmpty)
      return _json(req.response, 401, {'error': 'Credenziali non valide'});
    final company = matches.first;
    final token = base64Url
        .encode(List<int>.generate(32, (_) => Random.secure().nextInt(256)))
        .replaceAll('=', '');
    sessions[token] = company['id'].toString();
    return _json(req.response, 200, {
      'token': token,
      'company': {
        'id': company['id'],
        'companyName': company['companyName'],
        'email': company['email']
      }
    });
  }

  if (method == 'POST' && path == '/api/logout') {
    final token = _bearer(req);
    if (token != null) sessions.remove(token);
    return _json(req.response, 200, {'message': 'Logout effettuato'});
  }

  if (method == 'GET' && path == '/api/jobs') {
    final jobs = await _readList(jobsFile);
    jobs.sort((a, b) =>
        b['createdAt'].toString().compareTo(a['createdAt'].toString()));
    return _json(req.response, 200, jobs);
  }

  if (method == 'GET' && path == '/api/my/jobs') {
    final companyId = _companyId(req);
    if (companyId == null)
      return _json(req.response, 401, {'error': 'Autenticazione richiesta'});
    final jobs = await _readList(jobsFile);
    final mine = jobs.where((j) => j['companyId'] == companyId).toList();
    mine.sort((a, b) =>
        b['createdAt'].toString().compareTo(a['createdAt'].toString()));
    return _json(req.response, 200, mine);
  }

  if (method == 'POST' && path == '/api/jobs') {
    final companyId = _companyId(req);
    if (companyId == null)
      return _json(req.response, 401, {'error': 'Autenticazione richiesta'});
    final b = await _body(req);
    final title = (b['title'] ?? '').toString().trim();
    final description = (b['description'] ?? '').toString().trim();
    if (title.isEmpty || description.isEmpty) {
      return _json(req.response, 400,
          {'error': 'Titolo e descrizione sono obbligatori'});
    }
    final companies = await _readList(companiesFile);
    final company = companies.firstWhere((c) => c['id'] == companyId);
    final jobs = await _readList(jobsFile);
    final job = {
      'id': _id(),
      'companyId': companyId,
      'companyName': company['companyName'],
      'title': title,
      'description': description,
      'createdAt': DateTime.now().toIso8601String()
    };
    jobs.add(job);
    await _writeList(jobsFile, jobs);
    return _json(req.response, 201, job);
  }

  final jobApplications =
      RegExp(r'^/api/jobs/([^/]+)/applications$').firstMatch(path);
  if (method == 'GET' && jobApplications != null) {
    final companyId = _companyId(req);
    if (companyId == null)
      return _json(req.response, 401, {'error': 'Autenticazione richiesta'});
    final jobId = jobApplications.group(1);
    final jobs = await _readList(jobsFile);
    final job =
        jobs.where((j) => j['id'] == jobId && j['companyId'] == companyId);
    if (job.isEmpty)
      return _json(req.response, 404, {'error': 'Annuncio non trovato'});
    final applications = await _readList(applicationsFile);
    return _json(req.response, 200,
        applications.where((a) => a['jobId'] == jobId).toList());
  }

  final apply = RegExp(r'^/api/jobs/([^/]+)/applications$').firstMatch(path);
  if (method == 'POST' && apply != null) {
    final jobId = apply.group(1);
    final jobs = await _readList(jobsFile);
    if (!jobs.any((j) => j['id'] == jobId))
      return _json(req.response, 404, {'error': 'Annuncio non trovato'});
    final b = await _body(req);
    final name = (b['name'] ?? '').toString().trim();
    final surname = (b['surname'] ?? '').toString().trim();
    final email = (b['email'] ?? '').toString().trim();
    final cvName = (b['cvName'] ?? 'curriculum.pdf').toString();
    final cvBase64 = (b['cvBase64'] ?? '').toString();
    if (name.isEmpty || surname.isEmpty || email.isEmpty || cvBase64.isEmpty) {
      return _json(req.response, 400,
          {'error': 'Compila tutti i campi e allega il curriculum'});
    }
    if (!RegExp(r'^[^@\s]+@[^@\s]+\.[^@\s]+$').hasMatch(email)) {
      return _json(req.response, 400, {'error': 'Email non valida'});
    }
    List<int> bytes;
    try {
      bytes = base64Decode(cvBase64);
    } catch (_) {
      return _json(req.response, 400, {'error': 'File curriculum non valido'});
    }
    if (bytes.length > 8 * 1024 * 1024)
      return _json(req.response, 413, {'error': 'Il curriculum supera 8 MB'});
    if (bytes.length < 5 ||
        ascii.decode(bytes.take(5).toList(), allowInvalid: true) != '%PDF-') {
      return _json(req.response, 400,
          {'error': 'Il file allegato non sembra essere un PDF valido'});
    }
    final id = _id();
    final safeName = 'cv_$id.pdf';
    await File('${uploadsDir.path}/$safeName').writeAsBytes(bytes, flush: true);
    final application = {
      'id': id,
      'jobId': jobId,
      'name': name,
      'surname': surname,
      'email': email,
      'cvName': cvName,
      'cvFile': safeName,
      'createdAt': DateTime.now().toIso8601String()
    };
    final applications = await _readList(applicationsFile);
    applications.add(application);
    await _writeList(applicationsFile, applications);
    return _json(req.response, 201,
        {'message': 'Candidatura inviata', 'application': application});
  }

  final cv = RegExp(r'^/api/applications/([^/]+)/cv$').firstMatch(path);
  if (method == 'GET' && cv != null) {
    final companyId = _companyId(req);
    if (companyId == null)
      return _json(req.response, 401, {'error': 'Autenticazione richiesta'});
    final applicationId = cv.group(1);
    final applications = await _readList(applicationsFile);
    final found = applications.where((a) => a['id'] == applicationId);
    if (found.isEmpty)
      return _json(req.response, 404, {'error': 'Candidatura non trovata'});
    final app = found.first;
    final jobs = await _readList(jobsFile);
    if (!jobs
        .any((j) => j['id'] == app['jobId'] && j['companyId'] == companyId)) {
      return _json(req.response, 403, {'error': 'Non autorizzato'});
    }
    final file = File('${uploadsDir.path}/${app['cvFile']}');
    if (!await file.exists())
      return _json(req.response, 404, {'error': 'Curriculum non trovato'});
    req.response.statusCode = 200;
    req.response.headers.contentType = ContentType('application', 'pdf');
    req.response.headers.set(
      'Content-Disposition',
      'inline; filename="curriculum.pdf"',
    );
    await req.response.addStream(file.openRead());
    await req.response.close();
    return;
  }

  return _json(req.response, 404, {'error': 'Endpoint non trovato'});
}
