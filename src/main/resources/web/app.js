(function () {
  'use strict';

  // All text is inserted with textContent, never innerHTML, so user data can never run as script (XSS defence).
  var $ = function (id) { return document.getElementById(id); };
  var csrf = null;
  var page = 0;
  var editId = null;

  function show(text, kind) {
    var m = $('msg');
    m.textContent = text || '';
    m.className = kind || '';
  }

  function api(path, method, data) {
    var opts = { method: method || 'GET', credentials: 'same-origin', headers: {} };
    if (opts.method === 'POST') {
      opts.headers['Content-Type'] = 'application/x-www-form-urlencoded';
      if (csrf) opts.headers['X-CSRF-Token'] = csrf;
      opts.body = new URLSearchParams(data || {}).toString();
    }
    return fetch(path, opts).then(function (r) {
      return r.json().catch(function () { return null; }).then(function (j) {
        if (!r.ok) {
          var err = new Error((j && j.error) || 'Request failed');
          err.status = r.status;
          throw err;
        }
        return j;
      });
    });
  }

  function handleError(err) {
    if (err.status === 401 && csrf) {             // session ended
      showLogin('Your session has ended. Please sign in again.');
      return;
    }
    show(err.message, 'error');
  }

  function showLogin(message) {
    csrf = null;
    $('authView').hidden = false;
    $('appView').hidden = true;
    $('userBox').hidden = true;
    $('loginPass').value = '';
    show(message || '', message ? 'error' : '');
  }

  function showApp(user) {
    csrf = user.csrf;
    $('whoami').textContent = 'Signed in as ' + user.username;
    $('authView').hidden = true;
    $('appView').hidden = false;
    $('userBox').hidden = false;
    $('date').value = new Date().toLocaleDateString('en-CA');   // YYYY-MM-DD in local time
    show('');
    resetForm();
    loadExpenses();
  }

  function cell(text, cls) {
    var td = document.createElement('td');
    td.textContent = text;
    if (cls) td.className = cls;
    return td;
  }

  function loadExpenses() {
    var q = new URLSearchParams({ page: String(page) });
    if ($('filter').value) q.set('category', $('filter').value);
    api('/api/expenses?' + q.toString()).then(function (d) {
      var rows = $('rows');
      rows.textContent = '';
      d.items.forEach(function (e) {
        var tr = document.createElement('tr');
        tr.appendChild(cell(e.date));
        tr.appendChild(cell(e.category.charAt(0) + e.category.slice(1).toLowerCase()));
        tr.appendChild(cell(e.description));
        tr.appendChild(cell(e.amount, 'num'));
        var actions = document.createElement('td');
        actions.className = 'num';
        var edit = document.createElement('button');
        edit.type = 'button'; edit.className = 'secondary'; edit.textContent = 'Edit';
        edit.addEventListener('click', function () { startEdit(e); });
        var del = document.createElement('button');
        del.type = 'button'; del.textContent = 'Delete';
        del.addEventListener('click', function () { removeExpense(e); });
        actions.appendChild(edit); actions.appendChild(del);
        tr.appendChild(actions);
        rows.appendChild(tr);
      });
      $('empty').hidden = d.items.length > 0;
      $('total').textContent = d.total;
      $('count').textContent = String(d.count);
      var pages = Math.max(1, Math.ceil(d.count / d.pageSize));
      $('pageInfo').textContent = 'Page ' + (d.page + 1) + ' of ' + pages;
      $('prevBtn').disabled = d.page <= 0;
      $('nextBtn').disabled = d.page + 1 >= pages;
    }).catch(handleError);
  }

  function resetForm() {
    editId = null;
    $('formTitle').textContent = 'Add expense';
    $('saveBtn').textContent = 'Add';
    $('cancelBtn').hidden = true;
    $('amount').value = '';
    $('description').value = '';
    $('category').value = 'FOOD';
  }

  function startEdit(e) {
    editId = e.id;
    $('formTitle').textContent = 'Edit expense';
    $('saveBtn').textContent = 'Save changes';
    $('cancelBtn').hidden = false;
    $('amount').value = e.amount;
    $('category').value = e.category;
    $('description').value = e.description;
    $('date').value = e.date;
    $('amount').focus();
  }

  function removeExpense(e) {
    if (!window.confirm('Delete this expense?')) return;
    api('/api/expenses/delete', 'POST', { id: String(e.id) })
      .then(function () { show('Expense deleted.', 'ok'); loadExpenses(); })
      .catch(handleError);
  }

  $('loginForm').addEventListener('submit', function (ev) {
    ev.preventDefault();
    api('/api/login', 'POST', { username: $('loginUser').value, password: $('loginPass').value })
      .then(function (u) { $('loginPass').value = ''; showApp(u); })
      .catch(handleError);
  });

  $('registerForm').addEventListener('submit', function (ev) {
    ev.preventDefault();
    api('/api/register', 'POST', { username: $('regUser').value, password: $('regPass').value })
      .then(function () {
        $('regPass').value = '';
        show('Account created. You can now sign in.', 'ok');
      }).catch(handleError);
  });

  $('expenseForm').addEventListener('submit', function (ev) {
    ev.preventDefault();
    var data = {
      amount: $('amount').value, category: $('category').value,
      description: $('description').value, date: $('date').value
    };
    var path = '/api/expenses';
    if (editId !== null) { data.id = String(editId); path = '/api/expenses/update'; }
    api(path, 'POST', data).then(function () {
      show(editId !== null ? 'Expense updated.' : 'Expense added.', 'ok');
      resetForm();
      loadExpenses();
    }).catch(handleError);
  });

  $('cancelBtn').addEventListener('click', resetForm);
  $('filter').addEventListener('change', function () { page = 0; loadExpenses(); });
  $('prevBtn').addEventListener('click', function () { if (page > 0) { page--; loadExpenses(); } });
  $('nextBtn').addEventListener('click', function () { page++; loadExpenses(); });
  $('logoutBtn').addEventListener('click', function () {
    api('/api/logout', 'POST', {}).catch(function () {}).then(function () { showLogin('You have been signed out.'); });
  });

  // On page load, resume an existing session if there is one.
  api('/api/me').then(showApp).catch(function () { showLogin(''); });
})();
