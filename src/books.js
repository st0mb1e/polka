// Список книг в каталоге.
export const books = Object.freeze([
  { id: 'little-prince', title: 'Маленький принц', author: 'Антуан де Сент-Экзюпери' },
  { id: 'master-margarita', title: 'Мастер и Маргарита', author: 'Михаил Булгаков' },
  { id: '1984', title: '1984', author: 'Джордж Оруэлл' },
  { id: 'pride-prejudice', title: 'Гордость и предубеждение', author: 'Джейн Остин' },
  { id: 'crime-punishment', title: 'Преступление и наказание', author: 'Фёдор Достоевский' },
  { id: 'sherlock', title: 'Приключения Шерлока Холмса', author: 'Артур Конан Дойл' },
  { id: 'alice', title: 'Алиса в Стране чудес', author: 'Льюис Кэрролл' },
  { id: 'seneca', title: 'Нравственные письма к Луцилию', author: 'Луций Анней Сенека' },
]);

export const bookIds = new Set(books.map((book) => book.id));
export const shelfStatuses = new Set(['planned', 'reading', 'read']);
