    async function deleteNote(idx) {
      if (!confirm('Вы уверены?')) return;
      try {
        const response = await fetch(API + '/admin/notes/delete', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ index: idx, admin_login: current, admin_password: currentPass })
        });
        if (response.ok) refreshNotes();
      } catch (e) {
        alert('Ошибка');
      }
    }

    async function deleteOwnNote(idx) {
      if (!confirm('Удалить этот материал?')) return;
      try {
        const response = await fetch(API + '/materials/delete', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ index: idx, username: current })
        });
        if (response.ok) {
          alert('Материал удален');
          refreshNotes();
        } else {
          const err = await response.json();
          alert(err.error || 'Ошибка удаления');
        }
      } catch (e) {
        alert('Ошибка сервера');
      }
    }

    async function assignOwnMaterial(idx) {
      const assignTo = prompt('Введите логин ученика (или оставьте пусто для удаления назначения):');
      if (assignTo === null) return;

      try {
        const response = await fetch(API + '/materials/assign', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ index: idx, assigned_to: assignTo, username: current })
        });
        if (response.ok) {
          alert('Материал назначен!');
          refreshNotes();
        } else {
          const err = await response.json();
          alert(err.error || 'Ошибка назначения');
        }
      } catch (e) {
        alert('Ошибка сервера');
      }
    }